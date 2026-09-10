#!/usr/bin/env python3
"""Generate labeled Git histories and benchmark the local secret scanner."""

from __future__ import annotations

import argparse
import base64
import contextlib
import io
import json
import os
import random
import shutil
import string
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scan import scan_repo


@dataclass(frozen=True)
class TruthLine:
    repo: str
    commit: str
    file_path: str
    line_start: int
    finding_type: str


@dataclass(frozen=True)
class RepoSpec:
    name: str
    path: Path
    commits_to_scan: int


def run(cmd: list[str], cwd: Path, env: dict[str, str] | None = None) -> str:
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return proc.stdout.strip()


def random_token(rng: random.Random, length: int, alphabet: str | None = None) -> str:
    chars = alphabet or (string.ascii_letters + string.digits)
    return "".join(rng.choice(chars) for _ in range(length))


def secret_line(rng: random.Random, repo_idx: int, commit_idx: int) -> tuple[str, str]:
    kind = (repo_idx + commit_idx) % 6
    if kind == 0:
        value = "AKIA" + random_token(rng, 16, string.ascii_uppercase + string.digits)
        return f'AWS_ACCESS_KEY_ID_{commit_idx} = "{value}"', "AWS Access Key"
    if kind == 1:
        value = random_token(rng, 40)
        return f'AWS_SECRET_ACCESS_KEY_{commit_idx} = "{value}"', "AWS Secret Key"
    if kind == 2:
        value = "ghp_" + random_token(rng, 40)
        return f'GITHUB_PAT_{commit_idx} = "{value}"', "GitHub Token"
    if kind == 3:
        value = "xoxb-" + random_token(rng, 12) + "-" + random_token(rng, 12)
        return f'SLACK_BOT_TOKEN_{commit_idx} = "{value}"', "Slack Token"
    if kind == 4:
        value = "sk_test_" + random_token(rng, 24)
        return f'STRIPE_KEY_{commit_idx} = "{value}"', "Stripe Key"
    value = "prod-" + random_token(rng, 18)
    return f'password = "{value}"  # benchmark_{commit_idx}', "Password Assignment"


def benign_entropy_line(repo_idx: int, commit_idx: int) -> str:
    payload = f"release-artifact-cache-key-{repo_idx:02d}-{commit_idx:02d}-not-a-secret"
    encoded = base64.b64encode(payload.encode("ascii")).decode("ascii")
    return f'artifact_fingerprint_{commit_idx} = "{encoded}"'


def neutral_line(repo_idx: int, commit_idx: int) -> str:
    return f"FEATURE_FLAG_{repo_idx}_{commit_idx} = True"


def append_line(repo_path: Path, rel_path: str, line: str) -> int:
    target = repo_path / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    existing_lines = target.read_text(encoding="utf-8").splitlines() if target.exists() else []
    line_no = len(existing_lines) + 1
    with target.open("a", encoding="utf-8") as f:
        f.write(line + "\n")
    return line_no


def commit_env(repo_idx: int, commit_idx: int) -> dict[str, str]:
    env = dict(os.environ)
    minute = repo_idx * 1000 + commit_idx
    timestamp = f"2026-01-01T00:{minute % 60:02d}:00+00:00"
    env["GIT_AUTHOR_DATE"] = timestamp
    env["GIT_COMMITTER_DATE"] = timestamp
    return env


def create_repo(
    base_dir: Path,
    repo_idx: int,
    commits_per_repo: int,
    rng: random.Random,
) -> tuple[RepoSpec, list[TruthLine], int, int]:
    repo_name = f"synthetic-repo-{repo_idx:02d}"
    repo_path = base_dir / repo_name
    repo_path.mkdir(parents=True)

    run(["git", "init", "-q"], repo_path)
    run(["git", "config", "user.name", "Secret Scanner Benchmark"], repo_path)
    run(["git", "config", "user.email", "benchmark@example.invalid"], repo_path)

    (repo_path / "README.md").write_text("# Synthetic benchmark repo\n", encoding="utf-8")
    run(["git", "add", "README.md"], repo_path)
    run(["git", "commit", "-q", "-m", "initial benchmark seed"], repo_path, commit_env(repo_idx, 0))

    truth: list[TruthLine] = []
    benign_entropy_lines = 0
    neutral_lines = 0

    for commit_idx in range(commits_per_repo):
        rel_path = f"service_{commit_idx % 5}/settings.py"
        scenario = commit_idx % 4

        if scenario in {0, 1}:
            line, finding_type = secret_line(rng, repo_idx, commit_idx)
            is_secret = True
        elif scenario == 2:
            line = benign_entropy_line(repo_idx, commit_idx)
            finding_type = ""
            is_secret = False
            benign_entropy_lines += 1
        else:
            line = neutral_line(repo_idx, commit_idx)
            finding_type = ""
            is_secret = False
            neutral_lines += 1

        line_no = append_line(repo_path, rel_path, line)
        run(["git", "add", rel_path], repo_path)
        run(
            ["git", "commit", "-q", "-m", f"benchmark commit {commit_idx:03d}"],
            repo_path,
            commit_env(repo_idx, commit_idx + 1),
        )
        commit_hash = run(["git", "rev-parse", "HEAD"], repo_path)
        if is_secret:
            truth.append(TruthLine(repo_name, commit_hash, rel_path, line_no, finding_type))

    return RepoSpec(repo_name, repo_path, commits_per_repo), truth, benign_entropy_lines, neutral_lines


def finding_key(repo_name: str, finding: dict[str, Any]) -> tuple[str, str, str, int]:
    return (
        repo_name,
        str(finding.get("commit") or ""),
        str(finding.get("file_path") or ""),
        int(finding.get("line_start") or -1),
    )


def truth_key(truth: TruthLine) -> tuple[str, str, str, int]:
    return (truth.repo, truth.commit, truth.file_path, truth.line_start)


def score_predictions(
    truth_lines: list[TruthLine],
    findings_by_repo: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    truth = {truth_key(t) for t in truth_lines}
    predicted = {
        finding_key(repo_name, finding)
        for repo_name, findings in findings_by_repo.items()
        for finding in findings
    }

    true_positives = len(truth & predicted)
    false_positives = len(predicted - truth)
    false_negatives = len(truth - predicted)

    precision = true_positives / len(predicted) if predicted else 0.0
    recall = true_positives / len(truth) if truth else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )

    return {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "unique_predicted_lines": len(predicted),
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def run_profile(
    name: str,
    repos: list[RepoSpec],
    truth_lines: list[TruthLine],
    reports_dir: Path,
    min_confidence: float,
) -> dict[str, Any]:
    findings_by_repo: dict[str, list[dict[str, Any]]] = {}
    total_findings = 0
    total_raw_findings = 0
    total_files_touched = 0
    errors: list[str] = []

    start = time.perf_counter()
    for repo in repos:
        out_file = reports_dir / f"{repo.name}-{name}.json"
        with contextlib.redirect_stdout(io.StringIO()):
            scan_repo(
                str(repo.path),
                repo.commits_to_scan,
                str(out_file),
                use_llm=False,
                min_confidence=min_confidence,
            )
        data = json.loads(out_file.read_text(encoding="utf-8"))
        findings = data["findings"]
        findings_by_repo[repo.name] = findings
        stats = data.get("stats", {})
        total_findings += len(findings)
        total_raw_findings += int(stats.get("raw_findings") or len(findings))
        total_files_touched += int(stats.get("files_touched") or 0)
        errors.extend(data.get("errors") or [])
    runtime_seconds = time.perf_counter() - start

    scores = score_predictions(truth_lines, findings_by_repo)
    commits_scanned = sum(repo.commits_to_scan for repo in repos)
    duplicate_findings_collapsed = total_findings - scores["unique_predicted_lines"]

    return {
        "name": name,
        "llm_enabled": False,
        "min_confidence": min_confidence,
        "commits_scanned": commits_scanned,
        "files_touched": total_files_touched,
        "raw_findings": total_raw_findings,
        "findings_after_filter": total_findings,
        "duplicate_findings_collapsed": duplicate_findings_collapsed,
        "runtime_seconds": runtime_seconds,
        "commits_per_second": commits_scanned / runtime_seconds if runtime_seconds else 0.0,
        "errors": errors,
        **scores,
    }


def pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def render_markdown(results: dict[str, Any]) -> str:
    profiles = results["profiles"]
    baseline = profiles["baseline"]
    high_conf = profiles["high_confidence"]
    fp_reduction = results["comparison"]["false_positive_reduction"]

    lines = [
        "# Secret Scanner Benchmark Results",
        "",
        "Generated by `benchmarks/benchmark_scanner.py` using local synthetic Git histories.",
        "LLM analysis was disabled, so these numbers cover the regex, entropy, merge, path-filtering, and confidence-filtering pipeline.",
        "",
        "## Dataset",
        "",
        f"- Repositories: {results['dataset']['repositories']}",
        f"- Commits scanned: {results['dataset']['commits_scanned']}",
        f"- Files touched: {results['dataset']['files_touched']}",
        f"- Labeled secret lines: {results['dataset']['labeled_secret_lines']}",
        f"- Benign high-entropy distractor lines: {results['dataset']['benign_entropy_lines']}",
        f"- Neutral lines: {results['dataset']['neutral_lines']}",
        f"- Random seed: {results['dataset']['seed']}",
        "",
        "## Results",
        "",
        "| Profile | Min confidence | Findings | Unique lines | TP | FP | FN | Precision | Recall | F1 | Runtime | Throughput |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for profile in (baseline, high_conf):
        lines.append(
            "| {name} | {min_confidence:.2f} | {findings_after_filter} | "
            "{unique_predicted_lines} | {true_positives} | {false_positives} | "
            "{false_negatives} | {precision} | {recall} | {f1} | {runtime:.3f}s | "
            "{throughput:.1f} commits/s |".format(
                name=profile["name"],
                min_confidence=profile["min_confidence"],
                findings_after_filter=profile["findings_after_filter"],
                unique_predicted_lines=profile["unique_predicted_lines"],
                true_positives=profile["true_positives"],
                false_positives=profile["false_positives"],
                false_negatives=profile["false_negatives"],
                precision=pct(profile["precision"]),
                recall=pct(profile["recall"]),
                f1=pct(profile["f1"]),
                runtime=profile["runtime_seconds"],
                throughput=profile["commits_per_second"],
            )
        )
    lines.extend(
        [
            "",
            f"High-confidence filtering reduced line-level false positives by {pct(fp_reduction)} "
            f"({baseline['false_positives']} -> {high_conf['false_positives']}) on this benchmark.",
            "",
            "These are synthetic benchmark results, not a claim of production-world precision on arbitrary repositories.",
        ]
    )
    return "\n".join(lines) + "\n"


def build_results(args: argparse.Namespace) -> dict[str, Any]:
    rng = random.Random(args.seed)
    own_tempdir = args.workdir is None
    base_dir = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(prefix="secret-scanner-benchmark-"))
    reports_dir = base_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    try:
        repos: list[RepoSpec] = []
        truth: list[TruthLine] = []
        benign_entropy_lines = 0
        neutral_lines = 0

        for repo_idx in range(args.repos):
            repo, repo_truth, repo_benign_entropy, repo_neutral = create_repo(
                base_dir,
                repo_idx,
                args.commits_per_repo,
                rng,
            )
            repos.append(repo)
            truth.extend(repo_truth)
            benign_entropy_lines += repo_benign_entropy
            neutral_lines += repo_neutral

        baseline = run_profile("baseline", repos, truth, reports_dir, min_confidence=0.0)
        high_conf = run_profile(
            "high_confidence",
            repos,
            truth,
            reports_dir,
            min_confidence=args.high_confidence,
        )

        baseline_fp = baseline["false_positives"]
        high_conf_fp = high_conf["false_positives"]
        fp_reduction = (
            (baseline_fp - high_conf_fp) / baseline_fp
            if baseline_fp
            else 0.0
        )

        unique_files = {
            f"service_{commit_idx % 5}/settings.py"
            for commit_idx in range(args.commits_per_repo)
        }

        return {
            "dataset": {
                "repositories": args.repos,
                "commits_scanned": args.repos * args.commits_per_repo,
                "files_touched": args.repos * len(unique_files),
                "labeled_secret_lines": len(truth),
                "benign_entropy_lines": benign_entropy_lines,
                "neutral_lines": neutral_lines,
                "seed": args.seed,
            },
            "profiles": {
                "baseline": baseline,
                "high_confidence": high_conf,
            },
            "comparison": {
                "false_positive_reduction": fp_reduction,
                "false_positive_reduction_percent": fp_reduction * 100,
            },
        }
    finally:
        if own_tempdir and not args.keep_workdir:
            shutil.rmtree(base_dir, ignore_errors=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark the local secret scanner on synthetic Git histories")
    parser.add_argument("--repos", type=int, default=10, help="Number of synthetic repositories to create")
    parser.add_argument("--commits-per-repo", type=int, default=20, help="Benchmark commits per repository")
    parser.add_argument("--seed", type=int, default=1337, help="Random seed for generated secret values")
    parser.add_argument("--high-confidence", type=float, default=0.75, help="Confidence threshold for filtered profile")
    parser.add_argument("--workdir", type=Path, default=None, help="Optional directory for generated benchmark repos")
    parser.add_argument("--keep-workdir", action="store_true", help="Keep generated repos when using a temporary workdir")
    parser.add_argument("--json-out", type=Path, default=None, help="Optional JSON output path")
    parser.add_argument("--markdown-out", type=Path, default=None, help="Optional Markdown output path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    results = build_results(args)

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    if args.markdown_out:
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_out.write_text(render_markdown(results), encoding="utf-8")

    print(render_markdown(results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
