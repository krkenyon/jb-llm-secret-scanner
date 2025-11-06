import argparse
import json
import os
import re
import shutil
import tempfile
from pathlib import Path

import git
from git import NULL_TREE


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


def open_repo(path_or_url: str) -> tuple[git.Repo, str | None]:
    p = Path(path_or_url)
    if p.exists() and p.is_dir():
        return git.Repo(str(p)), None  # local repo
    # Treat as URL → clone into a temp dir
    tmpdir = tempfile.mkdtemp(prefix="jbscan_repo_")
    repo = git.Repo.clone_from(path_or_url, tmpdir)
    return repo, tmpdir


def scan_repo(path_or_url: str, n_commits: int, output_file: str):
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

            # Basic smoke-test: count diffs and print filenames
            print(f"[{commit.hexsha[:7]}] {commit.summary}")

            for d in diffs:
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

                    for patt_name, pattern in SECRET_PATTERNS:
                        match = re.search(pattern, clean_line)
                        if match:
                            results.append({
                                "commit": commit.hexsha,
                                "file_path": fname,
                                "line_snippet": clean_line.strip()[:200],
                                "finding_type": patt_name,
                                "rationale": f"Matched pattern: {patt_name}",
                                "confidence": 0.9
                            })

        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)

        print(f"\nWrote report to {output_file} (findings={len(results)})")

    finally:
        # Clean up temp clone if we created one
        if tmpdir and os.path.isdir(tmpdir):
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan last N commits for secrets (regex only)")
    parser.add_argument("--repo", required=True, help="Path or URL to Git repository")
    parser.add_argument("--n", type=int, required=True, help="Number of commits to scan")
    parser.add_argument("--out", required=True, help="Output JSON report path")
    args = parser.parse_args()

    scan_repo(args.repo, args.n, args.out)
