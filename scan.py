import argparse
import json
import os
import tempfile
import shutil
from pathlib import Path

import git
from git import NULL_TREE

def open_repo(path_or_url: str) -> tuple[git.Repo, str]:
    p = Path(path_or_url)
    if p.exists() and p.is_dir():
        return git.Repo(str(p)), None  # local repo
    # Treat as URL → clone into a temp dir
    tmpdir = tempfile.mkdtemp(prefix="jbscan_repo_")
    repo = git.Repo.clone_from(path_or_url, tmpdir)
    return repo, tmpdir

def scan_repo(path_or_url: str, n_commits: int, output_file: str):
    repo, tmpdir = open_repo(path_or_url)
    try:
        commits = list(repo.iter_commits("HEAD", max_count=n_commits))
        results = []

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
                # d.a_path or d.b_path depending on add/delete/modify
                fname = d.b_path or d.a_path
                print(f"  - {d.change_type} {fname}")

                # TODO: next step—scan d.diff.decode('utf-8', 'ignore') for secrets
                # and append structured findings to 'results'

        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nWrote report to {output_file} (findings={len(results)})")

    finally:
        # Clean up temp clone if we created one
        if tmpdir and os.path.isdir(tmpdir):
            shutil.rmtree(tmpdir, ignore_errors=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan last N commits for secrets")
    parser.add_argument("--repo", required=True, help="Path or URL to Git repository")
    parser.add_argument("--n", type=int, required=True, help="Number of commits to scan")
    parser.add_argument("--out", required=True, help="Output JSON report path")
    args = parser.parse_args()
    scan_repo(args.repo, args.n, args.out)
