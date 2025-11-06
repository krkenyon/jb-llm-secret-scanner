# 🧩 LLM-Powered Secret Scanner (Skeleton Version)

This is the initial skeleton for a command-line tool that scans the last *N* commits of a Git repository for secrets or other sensitive data.

At this stage, the tool collects commit diffs and displays changed files for each commit.  
Subsequent stages will add heuristic scanning (regex/entropy) and optional LLM validation.

---

## 🚀 Setup

Clone the repository and install dependencies:

```bash
git clone https://github.com/<yourusername>/jb-llm-secret-scanner.git
cd jb-llm-secret-scanner
pip install -r requirements.txt
```
---

## 🧠 Usage

Run the tool from the command line:

```bash
python scan.py --repo <path-or-url> --n <commits> --out report.json
```
---

## 📂 Output
For each commit, the tool prints a short summary to the console, like:

[8f3b97b] Fix API key handling
  - M src/config.py
  - A src/keys.py

At this stage, the generated report.json is an empty list:
[]