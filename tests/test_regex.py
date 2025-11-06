# tests/test_regex.py
import re
from scan import SECRET_PATTERNS

def hits(line: str):
    return [name for name, patt in SECRET_PATTERNS if re.search(patt, line)]

def test_aws_access_key():
    # Build token at runtime so it's not a literal in the repo
    akid = "AKIA" + ("A" * 16)  # 20 total chars after AKIA prefix
    line = f'AWS_ACCESS_KEY_ID = "{akid}"'
    assert "AWS Access Key" in hits(line)

def test_stripe_key():
    # 24 alnum chars after sk_test_
    key = "sk_" + "test_" + ("a1" * 12)
    line = f'STRIPE_KEY = "{key}"'
    assert "Stripe Key" in hits(line)

def test_github_token():
    # 40 chars after ghp_
    gh = "ghp_" + ("abcdEF12" * 5)
    line = f'token = "{gh}"'
    assert "GitHub Token" in hits(line)

def test_jwt_like():
    h = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    # ≥10 chars payload
    p = "eyJzdWIiOiIxMjM0NTY3ODkwIn0"  # typical-looking base64url payload
    s = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    jwt = f"{h}.{p}.{s}"
    line = f'JWT = "{jwt}"'
    assert "JWT" in hits(line)

def test_password_assignment():
    line = 'password = "supersecret123"'
    assert "Password Assignment" in hits(line)
