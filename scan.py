import argparse
import json
import os
import re
import sys
import shutil
import tempfile
from pathlib import Path
from math import log2

import git
from git import NULL_TREE
from openai import OpenAI

# ----------------------------------------------------
# Optional OpenAI setup (lazy)
# ----------------------------------------------------
from dotenv import load_dotenv
load_dotenv()

def get_openai_client_or_none():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None
    from openai import OpenAI
    return OpenAI(api_key=api_key)
'''
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

def should_ignore_path(p: str) -> bool:
    from pathlib import PurePosixPath
    if not p:
        return True
    parts = PurePosixPath(p).parts
    if any(part in IGNORE_DIRS for part in parts):
        return True
    if any(p.endswith(f) for f in IGNORE_FILES):
        return True
    return False
'''

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
        f.setdefault("finding_type", "Potential Secret")

        k = _key_for_merge(f)
        if k not in merged:
            merged[k] = f
        else:
            cur = merged[k]
            # keep highest confidence
            if f.get("confidence", 0) > cur.get("confidence", 0):
                cur["confidence"] = f["confidence"]
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

def analyze_commit_with_llm(commit_msg: str, diff_text: str):
    """
    Ask the LLM to find secrets or sensitive data in this commit.
    Returns a list of findings.
    """
    prompt = f"""
You are a security engineer reviewing a git commit diff.
Analyze the following diff and commit message for any potential secrets,
API keys, credentials, or other sensitive data.

Return JSON list of findings, each with:
  file_path
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
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are an expert security analyst."},
                {"role": "user", "content": prompt},
            ],
            temperature=0,
        )
        text = resp.choices[0].message.content.strip()
        data = extract_json_from_text(text)
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            return [data]
        return []
    except Exception as e:
        print(f"LLM analysis failed: {e}")
        return []



# ----------------------------------------------------
# Main scan loop
# ----------------------------------------------------
def scan_repo(path_or_url: str, n_commits: int, output_file: str, use_llm: bool = False, max_diff_chars: int = 12000):
    repo, tmpdir = open_repo(path_or_url)
    results = []

    try:
        commits = list(repo.iter_commits("HEAD", max_count=n_commits))
        for commit in commits:
            if commit.parents:
                parent = commit.parents[0]
                diffs = parent.diff(commit, create_patch=True)
            else:
                # initial commit
                diffs = commit.diff(NULL_TREE, create_patch=True)

            print(f"[{commit.hexsha[:7]}] {commit.summary}")
            

            # --- 1) LLM-first phase ---
            if use_llm:
                # Combine all added lines into one diff for the LLM
                combined_diff = ""
                for d in diffs:
                    fname = d.b_path or d.a_path
                    patch_text = d.diff.decode("utf-8", "ignore")
                    for line in patch_text.splitlines():
                        if line.startswith("+") and not line.startswith("+++"):
                            clean_line = line[1:]  # strip leading '+'
                            combined_diff += f"{fname}: {clean_line}\n"

                llm_findings = analyze_commit_with_llm(commit.message, combined_diff)
                for f in llm_findings:
                    f["commit"] = commit.hexsha
                    f["source"] = "llm"   # <= required for the tests to identify LLM findings
                    results.append(f)

            # --- 2) Optional heuristic phase (regex + entropy) ---
            for d in diffs:
                # Robust change-type derivation
                if getattr(d, "new_file", False):
                    ctype = "A"
                elif getattr(d, "deleted_file", False):
                    ctype = "D"
                else:
                    ctype = "M"  # default to modified

                # d.a_path or d.b_path depending on add/delete/modify
                fname = d.b_path or d.a_path
                print(f"  - {ctype} {fname}")
                if not fname or d.diff is None:
                    continue

                patch_text = d.diff.decode("utf-8", "ignore")

                # Scan only added lines
                for line in patch_text.splitlines():
                    if not line.startswith("+") or line.startswith("+++"):
                        continue
                    clean_line = line[1:]

                    # Regex pass
                    for patt_name, pattern in SECRET_PATTERNS:
                        if re.search(pattern, clean_line):
                            results.append({
                                "commit": commit.hexsha,
                                "file_path": fname,
                                "line_snippet": clean_line.strip()[:200],
                                "finding_type": patt_name,
                                "rationale": f"Matched pattern: {patt_name}",
                                "confidence": 0.9,
                                "source": "regex"
                            })

                    # Entropy pass
                    for tok in BASE64_LIKE.findall(clean_line):
                        if len(tok) < ENTROPY_MIN_LEN:
                            continue
                        if PURE_HEX.match(tok) or UUID_LIKE.match(tok):
                            continue
                        H = shannon_entropy(tok)
                        if H >= ENTROPY_THRESHOLD:
                            conf = min(1.0, max(0.0, (H - 3.0) / 3.0))
                            results.append({
                                "commit": commit.hexsha,
                                "file_path": fname,
                                "line_snippet": tok[:200],
                                "finding_type": "High-Entropy String",
                                "rationale": f"High-entropy token detected (H≈{H:.2f}).",
                                "confidence": round(conf, 2),
                                "source": "entropy"
                            })
        # Merge duplicates and bump confidence/source/rationale
        merged = merge_findings(results)

        with open(output_file, "w") as f:
            json.dump(merged, f, indent=2)
        print(f"\nWrote report to {output_file} (findings={len(merged)})")

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

    args = parser.parse_args()
    scan_repo(args.repo, args.n, args.out, use_llm=args.use_llm, max_diff_chars=args.max_diff_chars)
