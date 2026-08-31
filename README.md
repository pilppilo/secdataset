# Curated Cybersecurity Dataset for Azure AI Foundry (Phi-4 / Phi-3.5 / Ministral-3B)

Curated, de-duplicated fine-tuning dataset formatted strictly for **Azure AI Foundry JSONL** (`{"messages": [{"role":"system"},{"role":"user"},{"role":"assistant"}]}`) for training defensive cybersecurity and static analysis assistants (vulnerability detection, taint flow analysis, CWE classification, and secure remediation).

* **Training Set:** [`train.jsonl`](file:///home/owner/secdata/train.jsonl) (**80%** — **8,000 samples**, 28 MB)
* **Validation Set:** [`val.jsonl`](file:///home/owner/secdata/val.jsonl) / [`validation.jsonl`](file:///home/owner/secdata/validation.jsonl) (**20%** — **2,000 samples**, 6.9 MB)
* **Total Formatted Samples:** **10,000 samples** extracted and normalized directly from `Vyber07/cyber-security`.
* **Format:** Strict single-line JSONL conforming to Azure AI Foundry specifications.
* **License:** Apache-2.0 (see [`DATASET_README.md`](file:///home/owner/secdata/DATASET_README.md) for upstream dataset card).

---

## 1. Why You Must Include a Validation Set

For cybersecurity and code analysis fine-tuning tasks, having a dedicated validation set protects against subtle training failures:

* **Overfitting Detection:** It calculates **Validation Loss** alongside Training Loss at each checkpoint. If training loss drops while validation loss starts rising, the model is memorizing specific variable names and comments rather than learning true vulnerability logic.
* **Token Accuracy & Generalization:** It verifies whether the model can accurately identify CWEs and write secure code for fresh snippets it didn't see during training.
* **Zero Data Leakage:** Both sets are verified with SHA-256 prompt hashing to ensure **0% prompt contamination** between train and val.

---

## 2. Dataset Schema & Structure

Each record occupies exactly **one single line** with no unescaped multi-line formatting:

```json
{"messages": [{"role": "system", "content": "You are an expert static analysis security tool and vulnerability detection engine. Detect vulnerabilities, trace taint paths, identify CWE classifications, and provide secure remediation code."}, {"role": "user", "content": "Analyze this code for flaws:\n\n```c\nvoid get_user(char *src) {\n    char buf[16];\n    strcpy(buf, src);\n}\n```"}, {"role": "assistant", "content": "### Vulnerability Analysis\n- **Vulnerability:** CWE-120 (Buffer Copy without Checking Size of Input)\n- **Taint / Flow Analysis:**\n  - **Source:** Untrusted input parameter `char *src`.\n  - **Sink:** `strcpy` does not bound input size into `buf[16]`.\n- **Root Cause:** Lack of bounds checking allows stack buffer overflow.\n- **Remediation:**\n```c\n#include <string.h>\n\nvoid get_user(const char *src) {\n    char buf[16];\n    if (src == NULL) return;\n    strncpy(buf, src, sizeof(buf) - 1);\n    buf[sizeof(buf) - 1] = '\\0';\n}\n```"}]}
```

---

## 3. Repository Layout & Tools

```
.
├── train.jsonl               # Azure AI Foundry training set (80%)
├── val.jsonl                 # Azure AI Foundry validation set (20%)
├── validation.jsonl          # Synced copy of val.jsonl
├── build_curated_dataset.py  # Builds curated vulnerability dataset with 80/20 split
├── split_dataset.py          # Splits any raw JSONL dataset into train & val with dedup
├── convert_dataset.py        # Converts HF/local data into Azure JSONL format
├── validate_dataset.py       # Strict validation & cross-split leakage suite
├── DATASET_README.md         # Upstream dataset documentation (Vyber07/cyber-security)
└── README.md                 # Project guide
```

---

## 4. Validating Your Datasets

Run the validator before submitting your fine-tuning job to Azure AI Foundry:

```bash
python3 validate_dataset.py train.jsonl val.jsonl
```

### Checks Executed:
1. **Azure Schema & JSONL Syntax:** Validates single-line JSON, required `messages` array, lowercase roles (`system`, `user`, `assistant`), and turn sequence.
2. **0% Contamination Verification:** SHA-256 cross-checks every prompt in `train.jsonl` against `val.jsonl` to ensure zero data leakage.
3. **Split Balance Check:** Confirms ratio is within the optimal 80/20 to 85/15 range.
4. **Structured Security Reasoning:** Confirms assistant outputs contain CWE IDs, root cause / taint analysis, and secure fix code blocks.
5. **Context Limit Estimator:** Analyzes token counts to guarantee compliance with model context windows.

---

## 5. Splitting Your Own Data

To split any raw dataset into an 80/20 or 85/15 split with automatic deduplication:

```bash
python3 split_dataset.py --input my_security_dataset.jsonl --train-out train.jsonl --val-out val.jsonl --ratio 0.80 --seed 42
```

---

## 6. Converting Upstream Hugging Face Data (`Vyber07/cyber-security`)

```bash
# Set your Hugging Face access token for gated repository access
export HF_TOKEN="hf_your_token_here"

# Download and convert directly into 80/20 split
python3 convert_dataset.py --download-hf --max-hf-files 50 --train-out train.jsonl --val-out val.jsonl --val-ratio 0.20
```

---

## 7. Submitting to Azure AI Foundry

1. Navigate to **[Azure AI Foundry Portal](https://ai.azure.com/)**.
2. Go to **Fine-tuning** $\rightarrow$ **+ Fine-tune model**.
3. Select your base model: **Phi-4** (or `Phi-3.5-mini-instruct` / `Ministral-3B`).
4. In the **Training data** section, upload [`train.jsonl`](file:///home/owner/secdata/train.jsonl).
5. In the **Validation data** section, upload [`val.jsonl`](file:///home/owner/secdata/val.jsonl).
6. Configure hyperparameters (e.g., Learning Rate: `2e-5`, Epochs: `3-5`, Batch Size: `4-8`) and start training.
