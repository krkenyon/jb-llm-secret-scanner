import argparse
import hashlib
import json
import os
import re
import shutil
import tempfile
from fnmatch import fnmatch
from pathlib import Path
from math import log2
from datetime import datetime, timezone

import git
from git import NULL_TREE

# ----------------------------------------------------
# Optional OpenAI setup (lazy)
# ----------------------------------------------------
from dotenv import load_dotenv
load_dotenv()

LLM_MODEL = "gpt-4o-mini"

def get_openai_client_or_none():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None
    try:
        from openai import OpenAI
    except ImportError:
        return None
    return OpenAI(api_key=api_key)

def load_llm_cache(cache_file: str | None) -> dict[str, list[dict]]:
    if not cache_file:
        return {}
    path = Path(cache_file)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}

def save_llm_cache(cache_file: str | None, cache: dict[str, list[dict]]) -> None:
    if not cache_file:
        return
    path = Path(cache_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cache, indent=2))

def _llm_cache_key(commit_msg: str, diff_text: str) -> str:
    payload = json.dumps(
        {"model": LLM_MODEL, "commit_msg": commit_msg, "diff_text": diff_text},
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

# ----------------------------------------------------
# Ignore lists for paths
# ----------------------------------------------------

IGNORE_DIRS = {".git", ".venv", "node_modules", "dist", "build", "target", "__pycache__"}
IGNORE_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock", "poetry.lock"}
BINARY_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".jar", ".wasm"}

def is_binary_diff(d) -> bool:
    try:
        if getattr(d, "a_blob", None) and d.a_blob is not None and d.a_blob.binary:
            return True
        if getattr(d, "b_blob", None) and d.b_blob is not None and d.b_blob.binary:
            return True
    except Exception:
        pass
    # Fallback by extension
    import os
    p = (d.b_path or d.a_path or "").lower()
    _, ext = os.path.splitext(p)
    return ext in BINARY_EXTS

def should_ignore_path(p: str, extra_patterns: list[str] | None = None) -> bool:
    from pathlib import PurePosixPath
    if not p:
        return True
    parts = PurePosixPath(p).parts
    if any(part in IGNORE_DIRS for part in parts):
        return True
    if any(p.endswith(f) for f in IGNORE_FILES):
        return True
    if extra_patterns and any(fnmatch(p, pattern) for pattern in extra_patterns):
        return True
    return False


# ------------------------
# Simple regex patterns for secrets
# ------------------------
SECRET_PATTERNS = [
    ("AWS Access Key", r"\b(A3T|AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("AWS Secret Key", r"(?<![A-Za-z0-9/+=])(?P<key>[A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"),
    ("Generic Private Key", r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP|PRIVATE) KEY-----"),
    ("GitHub Token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ("Slack Token", r"\b(xox[baprs]-[A-Za-z0-9-]{10,48})\b"),
    ("Stripe Key", r"\bsk_(live|test)_[0-9a-zA-Z]{24,}\b"),
    ("JWT", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ("Password Assignment", r"(?i)(password|secret|token|api[_-]?key)\s*[:=]\s*['\"][^'\"]{6,}['\"]"),
]

# ------------------------
# Entropy scanning config
# ------------------------
ENTROPY_MIN_LEN = 20             # tokens shorter than this are rarely real secrets
ENTROPY_THRESHOLD = 3.5          # bits/char; raise to reduce noise
BASE64_LIKE = re.compile(r"\b[A-Za-z0-9+/_-]{20,}={0,2}\b")  # catch base64-ish/ID-like
PURE_HEX = re.compile(r"^[0-9a-fA-F]+$")
UUID_LIKE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)

# --------------------------------------------
# Shannon Entropy Calculator
# --------------------------------------------
# Measures the "randomness" or information content of a string.
#
# Formula (in bits per character):
#     H = -Σ (p_i * log2(p_i))
#
# where:
#   p_i = frequency of character i in the string.
#
# - Low entropy (≈0–2): predictable or structured strings ("AAAAAA", "password123")
# - High entropy (≈3.5–5): random-looking strings (API keys, JWTs, secrets)
#
# Example:
#   "AAAAAA"       → H = 0.0
#   "abc123"       → H ≈ 2.6
#   "sk_live_..."  → H ≈ 4.2
#   "eyJhbGciOi..." → H ≈ 4.5
#
# In this project:
#   Used to flag potential secrets with high entropy (>3.5 bits/char).
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    H = 0.0
    L = len(s)
    for c in counts.values():
        p = c / L
        H -= p * log2(p)
    return H


# ----------------------------------------------------
# Open a repository (local or remote)
# ----------------------------------------------------
def open_repo(path_or_url: str) -> tuple[git.Repo, str | None]:
    p = Path(path_or_url)
    if p.exists() and p.is_dir():
        return git.Repo(str(p)), None  # local repo
    # Treat as URL → clone into a temp dir
    tmpdir = tempfile.mkdtemp(prefix="jbscan_repo_")
    repo = git.Repo.clone_from(path_or_url, tmpdir)
    return repo, tmpdir

# ----------------------------------------------------
# Merge findings from multiple sources
# ----------------------------------------------------
def _combine_confidence(c1: float, c2: float) -> float:
    """Combine two confidence values with diminishing returns."""
    # Simple probabilistic union: 1 - (1-c1)*(1-c2)
    # Ensures the combined score is higher than either input but never >1.0
    combined = 1 - (1 - min(1, c1)) * (1 - min(1, c2))
    return round(min(1.0, combined), 3)

def _confidence(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default

def _key_for_merge(f: dict) -> tuple:
    return (
        f.get("commit"),
        f.get("file_path") or f.get("path") or "",
        (f.get("line_snippet") or f.get("snippet") or "")[:160].strip().lower()
    )

def merge_findings(findings: list[dict]) -> list[dict]:
    merged = {}
    for f in findings:
        f.setdefault("confidence", 0.5)
        f["confidence"] = _confidence(f.get("confidence"), 0.5)
        f.setdefault("finding_type", "Potential Secret")

        k = _key_for_merge(f)
        if k not in merged:
            merged[k] = f
        else:
            cur = merged[k]
            cur_confidence = _confidence(cur.get("confidence"))
            new_confidence = _confidence(f.get("confidence"))
            cur["confidence"] = _combine_confidence(cur_confidence, new_confidence)
            # keep highest confidence
            if new_confidence > cur_confidence:
                cur["finding_type"] = f.get("finding_type", cur.get("finding_type"))
                # prefer path if missing
                if not cur.get("file_path") and f.get("file_path"):
                    cur["file_path"] = f["file_path"]
            # concat rationales
            r1 = cur.get("rationale", "")
            r2 = f.get("rationale", "")
            merged[k]["rationale"] = " | ".join(x for x in [r1, r2] if x).strip()
            # combine sources
            srcs = set((cur.get("source","") + "," + f.get("source","")).split(","))
            merged[k]["source"] = ",".join(sorted(s for s in srcs if s))
    return list(merged.values())

# ----------------------------------------------------
# Build final report structure
# ----------------------------------------------------
def make_report(
    repo_source: str,
    commits_scanned: list[str],
    findings: list,
    errors: list[str],
    files_touched: int | None = None,
    raw_findings: int | None = None,
    min_confidence: float = 0.0,
    llm_cache_entries: int | None = None,
):
    return {
        "repo": repo_source,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "commit_window": {
            "n": len(commits_scanned),
            "from": commits_scanned[-1] if commits_scanned else None,
            "to": commits_scanned[0] if commits_scanned else None,
        },
        "findings": findings,
        "stats": {
            "commits_scanned": len(commits_scanned),
            "findings": len(findings),
            "raw_findings": raw_findings if raw_findings is not None else len(findings),
            "files_touched": files_touched,
            "min_confidence": min_confidence,
            "llm_cache_entries": llm_cache_entries,
        },
        "errors": errors,
    }

# ----------------------------------------------------
# Patch parsing: iterate added lines with line numbers
# ----------------------------------------------------
HUNK_RE = re.compile(r'^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,(?P<count>\d+))? @@')

def iter_added_lines_with_lineno(patch_text: str):
    """
    Yield tuples: (lineno, text) for added lines in a unified diff patch.
    """
    curr = None
    for raw in patch_text.splitlines():
        if raw.startswith('@@'):
            m = HUNK_RE.match(raw)
            if m:
                start = int(m.group('start'))
                curr = {"lineno": start}
            continue
        if curr is None:
            continue
        if raw.startswith('+') and not raw.startswith('+++'):
            yield curr["lineno"], raw[1:]
            curr["lineno"] += 1
        elif raw.startswith('-') and not raw.startswith('---'):
            # deletion does not advance target line
            pass
        else:
            # context line
            curr["lineno"] += 1

# ----------------------------------------------------
# Build combined added diff for LLM analysis
# ----------------------------------------------------
def build_combined_added_diff(diffs, max_chars: int, exclude_paths: list[str] | None = None):
    parts = []
    used = 0
    for d in diffs:
        fname = d.b_path or d.a_path
        if should_ignore_path(fname, exclude_paths) or is_binary_diff(d) or d.diff is None:
            continue
        patch_text = d.diff.decode("utf-8", "ignore")
        file_lines = []
        for lineno, clean_line in iter_added_lines_with_lineno(patch_text):
            s = f"{fname}:{lineno}: {clean_line}\n"
            if used + len(s) > max_chars:
                break
            file_lines.append(s)
            used += len(s)
        if file_lines:
            parts.append("".join(file_lines))
        if used >= max_chars:
            break
    return "".join(parts)

# ----------------------------------------------------
# LLM analysis of commit
# ----------------------------------------------------
def extract_json_from_text(text: str):
    """
    Extract the first valid JSON array/object from a text block.
    Handles Markdown code fences like ```json ... ```.
    Returns [] if nothing parseable is found.
    """
    t = text.strip()

    # If fenced, prefer the fenced content
    m = re.search(r"```(?:json)?\s*(.*?)\s*```", t, re.S | re.I)
    if m:
        t = m.group(1).strip()

    # Try direct parse
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        # Fallback: grab first {...} or [...] chunk
        m2 = re.search(r"(\{.*\}|\[.*\])", t, re.S)
        if m2:
            try:
                return json.loads(m2.group(1))
            except json.JSONDecodeError:
                pass
    return []

def analyze_commit_with_llm(
    commit_msg: str,
    diff_text: str,
    cache: dict[str, list[dict]] | None = None,
):
    """
    Ask the LLM to find secrets or sensitive data in this commit.
    Returns a list of findings.
    """
    cache_key = _llm_cache_key(commit_msg, diff_text)
    if cache is not None and cache_key in cache:
        return [dict(item) for item in cache[cache_key]]

    prompt = f"""
You are a security engineer reviewing a git commit diff.
Analyze the following diff and commit message for any potential secrets,
API keys, credentials, or other sensitive data.

Return JSON list of findings, each with:
  file_path
  line_start (first line number of the snippet)
  line_end   (same as line_start if single line)
  line_snippet
  finding_type
  rationale
  confidence (0.0–1.0)
Return ONLY valid JSON, with no extra commentary or text.

Commit message:
{commit_msg}

Diff:
{diff_text}
"""
    client = get_openai_client_or_none()
    if client is None:
        return []  # LLM disabled/missing key; safe no-op
    try:
        resp = client.chat.completions.create(
            model=LLM_MODEL,
            messages=[
                {"role": "system", "content": "You are an expert security analyst."},
                {"role": "user", "content": prompt},
            ],
            temperature=0,
        )
        text = resp.choices[0].message.content.strip()
        data = extract_json_from_text(text)
        if isinstance(data, list):
            findings = data
        elif isinstance(data, dict):
            findings = [data]
        else:
            findings = []
        if cache is not None:
            cache[cache_key] = findings
        return findings
    except Exception as e:
        print(f"LLM analysis failed: {e}")
        return []



# ----------------------------------------------------
# Main scan loop
# ----------------------------------------------------
def scan_repo(
    path_or_url: str,
    n_commits: int,
    output_file: str,
    use_llm: bool = False,
    max_diff_chars: int = 12000,
    min_confidence: float = 0.0,
    entropy_threshold: float = ENTROPY_THRESHOLD,
    exclude_paths: list[str] | None = None,
    llm_cache_file: str | None = None,
):
    repo, tmpdir = open_repo(path_or_url)
    results: list[dict] = []
    errors: list[str] = []
    touched_files: set[str] = set()
    llm_cache = load_llm_cache(llm_cache_file) if use_llm and llm_cache_file else None

    try:
        # Collect commits and hashes up-front for provenance in the report
        commits = list(repo.iter_commits("HEAD", max_count=n_commits))
        commit_hashes = [c.hexsha for c in commits]

        for commit in commits:
            try:
                if commit.parents:
                    parent = commit.parents[0]
                    diffs = parent.diff(commit, create_patch=True)
                else:
                    # initial commit
                    diffs = commit.diff(NULL_TREE, create_patch=True)

                print(f"[{commit.hexsha[:7]}] {commit.summary}")

                # --- 1) LLM-first phase (build combined diff only if enabled) ---
                if use_llm:
                    combined_diff = build_combined_added_diff(diffs, max_diff_chars, exclude_paths)
                    if combined_diff:
                        llm_findings = analyze_commit_with_llm(commit.message, combined_diff, llm_cache)
                        for f in llm_findings:
                            f["commit"] = commit.hexsha
                            f["source"] = "llm"  # tag for provenance/merging
                            results.append(f)

                # --- 2) Heuristic phase (regex + entropy) ---
                for d in diffs:
                    # Robust change-type derivation (debugging/trace)
                    if getattr(d, "new_file", False):
                        ctype = "A"
                    elif getattr(d, "deleted_file", False):
                        ctype = "D"
                    else:
                        ctype = "M"  # default to modified

                    fname = d.b_path or d.a_path
                    print(f"  - {ctype} {fname}")
                    if (
                        not fname
                        or d.diff is None
                        or should_ignore_path(fname, exclude_paths)
                        or is_binary_diff(d)
                    ):
                        continue
                    touched_files.add(fname)

                    patch_text = d.diff.decode("utf-8", "ignore")

                    # Iterate added lines WITH line numbers
                    for lineno, clean_line in iter_added_lines_with_lineno(patch_text):

                        # ---- Regex pass
                        for patt_name, pattern in SECRET_PATTERNS:
                            if re.search(pattern, clean_line):
                                results.append({
                                    "commit": commit.hexsha,
                                    "file_path": fname,
                                    "line_start": lineno,   # immediately after file_path
                                    "line_end": lineno,
                                    "line_snippet": clean_line.strip()[:200],
                                    "finding_type": patt_name,
                                    "rationale": f"Matched pattern: {patt_name}",
                                    "confidence": 0.9,
                                    "source": "regex",
                                })

                        # ---- Entropy pass
                        for tok in BASE64_LIKE.findall(clean_line):
                            if len(tok) < ENTROPY_MIN_LEN:
                                continue
                            if PURE_HEX.match(tok) or UUID_LIKE.match(tok):
                                continue
                            H = shannon_entropy(tok)
                            if H >= entropy_threshold:
                                conf = min(1.0, max(0.0, (H - 3.0) / 3.0))  # entropy → confidence
                                results.append({
                                    "commit": commit.hexsha,
                                    "file_path": fname,
                                    "line_start": lineno,   # immediately after file_path
                                    "line_end": lineno,
                                    "line_snippet": tok[:200],
                                    "finding_type": "High-Entropy String",
                                    "rationale": f"High-entropy token detected (H≈{H:.2f}).",
                                    "confidence": round(conf, 2),
                                    "source": "entropy",
                                })

            except Exception as e:
                # Capture per-commit errors but keep scanning
                msg = f"Commit {commit.hexsha[:7]} failed: {e}"
                print(f"⚠️ {msg}")
                errors.append(msg)

        # --- 3) Merge duplicates / combine sources & confidence
        merged = merge_findings(results)
        filtered = [f for f in merged if _confidence(f.get("confidence")) >= min_confidence]

        # --- 4) Build and write structured report
        report = make_report(
            path_or_url,
            commit_hashes,
            filtered,
            errors,
            files_touched=len(touched_files),
            raw_findings=len(merged),
            min_confidence=min_confidence,
            llm_cache_entries=len(llm_cache) if llm_cache is not None else None,
        )
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)
        if llm_cache is not None:
            save_llm_cache(llm_cache_file, llm_cache)

        print(f"\nWrote report to {output_file} (findings={len(filtered)}, errors={len(errors)})")

    finally:
        if tmpdir and os.path.isdir(tmpdir):
            shutil.rmtree(tmpdir, ignore_errors=True)


# ----------------------------------------------------
# CLI entry point
# ----------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LLM-powered secret scanner for Git commits")
    parser.add_argument("--repo", required=True, help="Path or URL to Git repository")
    parser.add_argument("--n", type=int, required=True, help="Number of commits to scan")
    parser.add_argument("--out", required=True, help="Output JSON report path")
    parser.add_argument("--llm", dest="use_llm", action="store_true", help="Enable LLM triage")
    parser.add_argument("--no-llm", dest="use_llm", action="store_false", help="Disable LLM triage (default)")
    parser.set_defaults(use_llm=False)
    parser.add_argument("--max-diff-chars", type=int, default=12000, help="Cap combined diff sent to LLM")
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        help="Only include findings at or above this confidence in the final report",
    )
    parser.add_argument(
        "--entropy-threshold",
        type=float,
        default=ENTROPY_THRESHOLD,
        help="Shannon entropy threshold for generic high-entropy token findings",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Additional path glob to skip; can be supplied more than once",
    )
    parser.add_argument(
        "--llm-cache",
        default=None,
        help="Optional JSON cache file for LLM findings",
    )

    args = parser.parse_args()
    scan_repo(
        args.repo,
        args.n,
        args.out,
        use_llm=args.use_llm,
        max_diff_chars=args.max_diff_chars,
        min_confidence=args.min_confidence,
        entropy_threshold=args.entropy_threshold,
        exclude_paths=args.exclude,
        llm_cache_file=args.llm_cache,
    )
