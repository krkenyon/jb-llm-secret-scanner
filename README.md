# JB-LLM-Secret-Scanner

A command-line tool to scan the last _N_ commits of a Git repository for secrets or other sensitive data, powered by heuristics (regex + entropy) **and optionally** a Large Language Model (LLM).

---

## 🔍 Why this tool

Hard-coded credentials, API keys, tokens and other secrets slipping into Git history are a real risk.  
This scanner helps automatically find:
- strings that match known secret patterns (e.g., AWS keys, Stripe keys) via **regex**
- random-looking tokens via **entropy analysis**
- contextual signals via an **LLM triage** (to reduce false positives)

---

## ✅ Features

- Works on a local path or a remote Git URL (automatically clones to a temp dir)  
- Scans the last `N` commits (you choose `N`)  
- Records added lines only (reducing noise)  
- Normalises findings into a JSON report with: commit hash, file path, line numbers, snippet, finding type, rationale, confidence, source  
- Optional LLM phase (if enabled) with caching to reduce cost  
- Easily filter by minimum confidence, exclude paths/globs, cap diff size  
- Test suite included (pytest) for integration and detection correctness  

---

## 🛠️ Setup

```bash
# clone the repo
git clone https://github.com/krkenyon/jb-llm-secret-scanner.git
cd jb-llm-secret-scanner

# create a virtual environment (optional but recommended)
python3 -m venv .venv
source .venv/bin/activate

# install dependencies
pip install -r requirements.txt

# (Optional) create a .env file for your OpenAI API key
echo "OPENAI_API_KEY=your_api_key_here" > .env
```
Note: You must have a valid OPENAI_API_KEY in your environment for the LLM phase to work. If it’s not set, the tool will run in “no-LLM” mode.

---

## 🚀 Usage

```bash
python scan.py \
  --repo /path/to/repo \
  --n 50 \
  --out report.json \
  [--llm] \
  [--no-llm] \
  [--min-confidence 0.6] \
  [--exclude "node_modules,dist,*.png"] \
  [--model gpt-4o-mini] \
  [--max-diff-chars 12000]
```
Options

--repo : Path or URL to Git repo

--n : Number of recent commits to scan

--out : Path for the JSON output report

--llm / --no-llm : Enable or disable LLM phase (default: disabled)

--min-confidence : Minimum confidence threshold for findings to be included

--exclude : Comma-separated glob/list of paths to skip

--model : Name of the LLM model to use (if LLM enabled)

--max-diff-chars : Maximum combined diff size sent to the LLM

---

## 📘 Example Output (report.json)

```json
{
  "repo": "/path/to/repo",
  "scanned_at": "2025-11-06T12:34:56Z",
  "commit_window": {
    "n": 10,
    "from": "abc1234",
    "to": "def5678"
  },
  "findings": [
    {
      "commit": "58deebfafa2cb11a82cd20fc2a479ad0689f0107",
      "file_path": "secrets.py",
      "line_start": 5,
      "line_end": 5,
      "line_snippet": "AWS_ACCESS_KEY_ID = \"AKIAAAAAAAAAAAAAAAAA\"",
      "finding_type": "AWS Access Key",
      "rationale": "Matched pattern: AWS Access Key | LLM: looks like a credential",
      "confidence": 0.95,
      "source": "regex,llm"
    },
    {
      "commit": "58deebfafa2cb11a82cd20fc2a479ad0689f0107",
      "file_path": "secrets.py",
      "line_start": 6,
      "line_end": 6,
      "line_snippet": "STRIPE_KEY = \"sk_test_a1a1a1a1a1a1a1a1a1a1a1a1\"",
      "finding_type": "Stripe Key",
      "rationale": "Matched pattern: Stripe Key",
      "confidence": 0.90,
      "source": "regex"
    }
  ],
  "stats": {
    "commits_scanned": 10,
    "findings": 2,
    "files_touched": null
  },
  "errors": []
}
```
---

## 🧪 Testing

Run the test suite with:
```bash
pytest -v
```
There are integration tests for:
regex/entropy scanning without LLM
LLM-enabled scans
If you add new detection patterns or adjust logic, make sure to add coverage there.

---

## ⚠️ Limitations & Future Work

This scanner focuses on added lines in commits, so secrets previously committed but unchanged might escape detection.
When two different secrets occur on the same line, merging logic may need further tuning to distinguish them.
LLM cost and latency: enabling --llm will incur API calls; caching helps but be mindful in CI.
Entropy thresholds and regex patterns may produce false positives (placeholders, test keys). Consider refining patterns or adding exclusions.

Future enhancements might include:
multi-line secret detection (private keys)
real-time CI integration (pre-commit hooks)
support for alternative LLM providers or self-hosted models

---

## 🧑‍💻 How it works (high level)

Clone or open provided repo path, fetch last n commits.
For each commit, build a diff of added lines.
Heuristic pass: scan each added line for:
regex matches → “finding_type” tags (AWS Access Key, Stripe Key, etc.)
high‐entropy tokens (via Shannon entropy) → generic “High-Entropy String” findings
LLM pass (optional): send a combined diff text to an LLM with prompt context; LLM returns findings with file_path, line_start, line_end, snippet, rationale, confidence.
Merge pass: combine overlapping findings (same commit + file + line/snippet overlap) from multiple sources → boost confidence, unify sources.
Write JSON report with metadata, findings, stats and optionally errors.

---

## 📄 License

MIT License — feel free to use, modify and integrate into CI/CD workflows.

---

## 💬 Contributing

Contributions welcome! Please open issues or pull requests for:
new secret-pattern regex rules
enhancements for entropy logic
improved LLM prompts for better context and fewer false positives
CI workflows or GitHub Actions integration
