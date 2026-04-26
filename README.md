# MAS-SZZ: Multi-Agentic SZZ Algorithm for Vulnerability-Inducing Commit Identification

A multi-agent framework for automatically identifying Vulnerability-Inducing Commits (VICs). Given a Vulnerability-Fixing Commit (VFC), the system traces back through git history using a three-stage LLM agent pipeline to locate the commit that introduced the vulnerability.


## Architecture

- **Stage 1: Root Cause Analysis** — Auditor agent generates a vulnerability root cause description; Judge agent verifies quality, with up to 3 retries
- **Stage 2: Anchor Statement Selection** — Parses patch hunks, groups by change intent, filters non-security-related changes, and pinpoints the code line most directly responsible for the vulnerability
- **Stage 3: Autonomous Repository Exploration** — Starting from the anchor line, iteratively runs `git blame` to trace back through commits; an LLM judges whether each historical commit contains the vulnerability until the VIC is found

## Structure

```
mas-szz/
├── run.py              # Batch entry point
├── pipeline.py         # Main controller, orchestrates three stages
├── data_types.py       # Global data structure definitions
├── prompts.py          # Prompt templates for all agents
├── llm.py              # LLM client (configure API key and base_url via env vars)
├── constants.py        # Hyperparameter config (MODEL_NAME, etc.)
├── agents/
│   ├── root_cause_agent.py         # Stage 1 Auditor
│   ├── root_cause_reviewer.py      # Stage 1 Judge
│   ├── grouping_agent.py           # Stage 2 hunk intent analysis and grouping
│   ├── reviewer_agent.py           # Stage 2 consistency check + vulnerability relevance filtering
│   ├── vuln_statement_agent.py     # Stage 2 anchor line localization
│   └── bic_agent.py                # Stage 3 git blame tracing, locates VIC
├── tools/              # Git operations, patch parsing, context retrieval
└── dataset/
```

## Dataset

Both datasets are JSON arrays. Each record has the following format:

```json
{
  "cveid": "CVE-2021-12345",
  "repo_name": "torvalds/linux",
  "fix_commit_hashes": ["abc123..."],
  "bug_commit_hash": "def456..."
}
```

`bug_commit_hash` is the ground truth VIC used for evaluation. To switch datasets, update `DS_KVIC_PATH` and `CVE_DESC_PATH` in `constants.py`.

## Installation

```bash
pip install openai tiktoken
```

## Setup

Clone the target repository to `repos/<repo_name>/` (matching the `repo_name` field in the dataset).

Set the following environment variables:

```bash
export OPENAI_API_KEY=your_api_key
export OPENAI_BASE_URL=your_base_url  # optional, defaults to OpenAI
```

## Run

```bash
python run.py
```
