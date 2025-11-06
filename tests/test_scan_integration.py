import tempfile, os, json, subprocess
from pathlib import Path
from scan import scan_repo


def make_test_repo():
    tmpdir = tempfile.mkdtemp()
    os.chdir(tmpdir)
    subprocess.run(["git", "init"], check=True)

    # Build fake secret-looking values at runtime
    akid = "AKIA" + ("A" * 16)               # 20 chars after prefix
    stripe = "sk_" + "test_" + ("a1" * 12)   # 24 chars after prefix

    Path("secrets.py").write_text(
        f'AWS_ACCESS_KEY_ID = "{akid}"\n'
        f'STRIPE_KEY = "{stripe}"\n'
    )
    subprocess.run(["git", "add", "."], check=True)
    subprocess.run(["git", "commit", "-m", "seed fake secrets"], check=True)
    return tmpdir


def test_scan_repo_detects_secrets(tmp_path):
    repo_path = make_test_repo()
    out = tmp_path / "report.json"
    scan_repo(repo_path, n_commits=1, output_file=str(out))
    data = json.load(open(out))
    types = {x["finding_type"] for x in data}
    assert "AWS Access Key" in types
    assert "Stripe Key" in types
