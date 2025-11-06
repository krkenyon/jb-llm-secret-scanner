import tempfile
import os
import json
import subprocess
from pathlib import Path
import pytest

from scan import scan_repo


def make_test_repo():
    """Create a temporary git repo with fake but secret-looking credentials."""
    tmpdir = tempfile.mkdtemp()
    os.chdir(tmpdir)
    subprocess.run(["git", "init"], check=True)

    akid = "AKIA" + ("A" * 16)               # AWS-style access key
    stripe = "sk_" + "test_" + ("a1" * 12)   # Stripe-style key

    Path("secrets.py").write_text(
        f'AWS_ACCESS_KEY_ID = "{akid}"\n'
        f'STRIPE_KEY = "{stripe}"\n'
    )
    subprocess.run(["git", "add", "."], check=True)
    subprocess.run(["git", "commit", "-m", "seed fake secrets"], check=True)
    return tmpdir


# ----------------------------------------------------------------------
# 1) No-LLM test (pure regex/entropy)
# ----------------------------------------------------------------------

def test_scan_repo_detects_secrets_no_llm(tmp_path):
    repo_path = make_test_repo()
    out = tmp_path / "report.json"
    scan_repo(repo_path, n_commits=1, output_file=str(out), use_llm=False)

    data = json.load(open(out))
    if isinstance(data, dict):  # full report form
        findings = data["findings"]
    else:
        findings = data

    types = {f["finding_type"] for f in findings}
    assert "AWS Access Key" in types
    assert "Stripe Key" in types

    # should not contain any LLM-sourced findings
    assert all("llm" not in (f.get("source") or "") for f in findings)


def test_scan_repo_detects_secrets_with_llm(tmp_path):
    repo_path = make_test_repo()
    out = tmp_path / "report.json"
    scan_repo(repo_path, n_commits=1, output_file=str(out), use_llm=True)

    data = json.load(open(out))
    if isinstance(data, dict):  # full report form
        findings = data["findings"]
    else:
        findings = data

    types = {f["finding_type"] for f in findings}
    assert "AWS Access Key" in types
    assert "Stripe Key" in types
    # should contain at least one LLM-sourced finding
    assert any("llm" in (f.get("source") or "") for f in findings)