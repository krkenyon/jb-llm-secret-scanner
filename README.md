# LLM-Secret-Scanner

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
  [--entropy-threshold 3.5] \
  [--exclude "tests/**"] \
  [--llm-cache .cache/jbscan-llm.json] \
  [--max-diff-chars 12000]
```
Options

--repo : Path or URL to Git repo

--n : Number of recent commits to scan

--out : Path for the JSON output report

--llm / --no-llm : Enable or disable LLM phase (default: disabled)

--min-confidence : Minimum confidence required in the final report

--entropy-threshold : Shannon entropy cutoff for generic high-entropy token findings

--exclude : Additional path glob to skip; can be supplied more than once

--llm-cache : Optional JSON cache file for LLM findings

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
    "raw_findings": 3,
    "files_touched": 2,
    "min_confidence": 0.6,
    "llm_cache_entries": 1
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
There are minimal integration tests for:
regex/entropy scanning without LLM
LLM-enabled scans
If you add new detection patterns or adjust logic, make sure to add coverage there.

---

## 📊 Benchmarking

Generate a reproducible synthetic benchmark with labeled secrets and benign distractor lines:

```bash
python benchmarks/benchmark_scanner.py \
  --repos 10 \
  --commits-per-repo 20 \
  --seed 1337 \
  --markdown-out docs/benchmark_results.md
```

The current saved benchmark scanned 10 generated repositories / 200 commits / 100 labeled secret lines. With `--min-confidence 0.75`, it reduced line-level false positives from 50 to 0 while keeping 100% recall on this synthetic benchmark. See `docs/benchmark_results.md` for the full table and caveats.

---

## ⚠️ Limitations & Future Work

This scanner focuses on added lines in commits, so secrets previously committed but unchanged might escape detection.
When two different secrets occur on the same line, merging logic may need further tuning to distinguish them.
LLM cost and latency: enabling --llm will incur API calls; use --llm-cache for repeated scans over the same diffs.
Entropy thresholds and regex patterns may produce false positives (placeholders, test keys). Consider refining patterns or adding exclusions.

Future enhancements might include:
- multi-line secret detection (private keys)
- real-time CI integration (pre-commit hooks)
- extension of the CLI to allow users to configure more runtime parameters (e.g. LLM model selection)
- support for alternative LLM providers or self-hosted models
- checks for personal information (e.g. Credit Card Numbers, Social Security Numbers, Phone Numbers, Names / Addresses)

---

## 🧑‍💻 How it works (high level)

Clone or open provided repo path, fetch last n commits.

For each commit, build a diff of added lines.

Heuristic pass: scan each added line for:

- regex matches → “finding_type” tags (AWS Access Key, Stripe Key, etc.)
- high‐entropy tokens (via Shannon entropy) → generic “High-Entropy String” findings

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
