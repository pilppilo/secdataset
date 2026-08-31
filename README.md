# secdataset — Curated Cybersecurity Dataset for Azure AI Foundry (Phi-4 / Phi-3.5)

Curated, de-duplicated fine-tuning dataset in **Azure AI Foundry JSONL** format (`{"messages": [{"role":"system"},{"role":"user"},{"role":"assistant"}]}`) for training a defensive cybersecurity assistant (vulnerability detection, secure remediation, SOC analysis).

* **Train:** `train.jsonl` (80%) · **Validation:** `validation.jsonl` (20%) — single-line JSONL, validated via `validate_dataset.py`.
* **License:** Apache-2.0 (see `DATASET_README.md` for full dataset card).

## Purpose

Build a high-quality, Phi-4-ready training set that:

* Detects vulnerabilities with taint-path / CWE classification (CWE-79, CWE-89, CWE-120, CWE-352, etc.) and proposes minimal secure fixes
* Covers defensive analysis across web, API, cloud, container, blockchain and AI/ML security
* Supports Azure AI Foundry fine-tuning without additional preprocessing

## Source & Provenance

| Component | Origin | Notes |
|-----------|--------|-------|
| **Raw upstream** | [`Vyber07/cyber-security`](https://huggingface.co/datasets/Vyber07/cyber-security) on Hugging Face | ~507 files / 16 GB across 30+ domains; aggregates open sources (see `DATASET_README.md` — MITRE ATT&CK, OWASP Top 10 / API / LLM / ML, NIST CSF/D3FEND, CIS Controls, PortSwigger Academy 31 topics, HackTheBox/TryHackMe/VulnHub labs, HackerOne/Bugcrowd reports, NVD/CISA/OSV, SANS, OpenThread/Thread, etc.). Gated files require `HF_TOKEN`. Raw downloads are **not committed** (`hf_downloaded_data/` is gitignored). |
| **Curated synthetic set** | `build_curated_dataset.py` | Hand-authored secure/insecure code pairs (C/C++, Python, JS/TS, Java, Go, PHP, Solidity) + SOC playbooks (Sigma/YARA/Snort/KQL). Defines `SYSTEM_PROMPT` used as the Azure `system` role. |
| **Converter** | `convert_dataset.py` | Normalizes ShareGPT / Instruction-Input-Output / code-vuln records → Azure `messages` format; deduplicates on `user` prefix; 80/20 shuffle (`--seed 42`); validates via `clean_and_validate_record()`. |
| **Validator** | `validate_dataset.py` | Strict Azure Foundry checks (valid JSON-per-line, `system`/`user`/`assistant` roles, non-empty content, token-length stats). |

> No personal data is included. Raw downloads and local token files (`.env`, `.hf_token`) are excluded by `.gitignore`.

## Repository Layout

```
.
├── train.jsonl               # Azure AI Foundry training set
├── validation.jsonl          # Azure AI Foundry validation set
├── DATASET_README.md         # Full upstream dataset card (domains, stats, sources)
├── build_curated_dataset.py  # Generates curated vulnerability examples
├── convert_dataset.py        # Converts HF/local data → Azure JSONL
├── validate_dataset.py       # Validates the JSONL files
└── .gitignore
```

## Usage

### Validate the committed trainset

```bash
python validate_dataset.py --input train.jsonl validation.jsonl
```

### Rebuild from local or HF sources

```bash
# From a local directory / file
python convert_dataset.py --input /path/to/data --train-out train.jsonl --val-out validation.jsonl --val-ratio 0.2

# From Hugging Face (requires token for gated files)
export HF_TOKEN=hf_xxx   # or --hf-token, or ~/.cache/huggingface/token
python convert_dataset.py --download-hf --hf-token "$HF_TOKEN" --max-hf-files 20
python convert_dataset.py --input hf_downloaded_data --train-out train.jsonl --val-out validation.jsonl
```

### Extend the curated set

Edit `CURATED_EXAMPLES` in `build_curated_dataset.py` and re-run its generation logic, then merge via `convert_dataset.py`.

## Reproducibility

* Deterministic 80/20 split (`seed=42`), dedup on first 200 chars of `user` content.
* `hf_downloaded_data/` is not tracked — rerun `--download-hf` to reproduce. See `DATASET_README.md` for upstream size/statistics (reported 16 GB / 507 files; local checkout size varies with `--max-hf-files`).

## Security & Privacy

* No secrets, credentials, or personal information are committed. Tokens are read from environment / HF cache at runtime only.
* `.gitignore` excludes `hf_downloaded_data/`, `*.json.gz`, `__pycache__/`, `.env`, `.hf_token`.
