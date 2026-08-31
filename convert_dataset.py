#!/usr/bin/env python3
"""
Convert Vyber07/cyber-security (or local cybersecurity datasets) to Azure AI Foundry JSONL format for Phi-4 / Phi-3.5 fine-tuning.

Format Requirement:
- Each line in train.jsonl / validation.jsonl is an independent single-line JSON object:
  {"messages": [{"role": "system", "content": "..."}, {"role": "user", "content": "..."}, {"role": "assistant", "content": "..."}]}
"""

import os
import sys
import json
import gzip
import re
import random
import argparse
import urllib.request
import urllib.error
from typing import List, Dict, Any, Generator, Optional, Tuple

DEFAULT_SYSTEM_PROMPT = (
    "You are an expert static analysis security tool and vulnerability detection engine. "
    "Detect vulnerabilities, trace taint paths, identify CWE classifications, and provide secure remediation code."
)

CWE_REGEX = re.compile(r"CWE[-_ ](\d+)", re.IGNORECASE)

def extract_cwe(text: str) -> Optional[str]:
    if not text:
        return None
    match = CWE_REGEX.search(text)
    if match:
        return f"CWE-{match.group(1)}"
    return None

def normalize_role(role: str) -> str:
    role = str(role).lower().strip()
    if role in ("system", "sys"):
        return "system"
    elif role in ("user", "human", "prompt", "input", "client"):
        return "user"
    elif role in ("assistant", "gpt", "bot", "response", "output", "completion", "model"):
        return "assistant"
    return "user"

def format_code_vulnerability_example(
    code: str,
    language: str = "c",
    cwe: Optional[str] = None,
    flaw: Optional[str] = None,
    details: Optional[str] = None,
    remediation: Optional[str] = None,
    custom_system: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    if not code or not (remediation or flaw or details or cwe):
        return None
    
    sys_prompt = custom_system or DEFAULT_SYSTEM_PROMPT
    user_prompt = f"Analyze this code for vulnerabilities and security flaws:\n\n```{language}\n{code.strip()}\n```"
    
    assistant_parts = ["### Vulnerability Analysis"]
    vuln_name = cwe or flaw or "Security Vulnerability"
    if cwe and flaw and cwe not in flaw:
        assistant_parts.append(f"- **Vulnerability:** {cwe} ({flaw})")
    else:
        assistant_parts.append(f"- **Vulnerability:** {vuln_name}")
    
    if details:
        assistant_parts.append(f"- **Root Cause / Taint Analysis:** {details.strip()}")
    elif flaw:
        assistant_parts.append(f"- **Root Cause / Taint Analysis:** {flaw.strip()}")
    
    if remediation:
        clean_rem = remediation.strip()
        if "```" not in clean_rem:
            assistant_parts.append(f"- **Remediation:**\n```{language}\n{clean_rem}\n```")
        else:
            assistant_parts.append(f"- **Remediation:**\n{clean_rem}")
    
    assistant_content = "\n".join(assistant_parts)
    
    return {
        "messages": [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": user_prompt},
            {"role": "assistant", "content": assistant_content}
        ]
    }

def process_raw_item(item: Any, source_name: str = "") -> List[Dict[str, Any]]:
    """Convert any unstructured/semi-structured record into list of Azure AI Foundry formatted messages."""
    results = []
    
    if not isinstance(item, dict):
        return results
    
    # 1. Check if already has messages list
    if "messages" in item and isinstance(item["messages"], list) and len(item["messages"]) >= 2:
        msgs = []
        has_system = False
        for m in item["messages"]:
            if isinstance(m, dict):
                r = normalize_role(m.get("role", "user"))
                c = str(m.get("content", "")).strip()
                if c:
                    if r == "system":
                        has_system = True
                    msgs.append({"role": r, "content": c})
        if msgs:
            if not has_system:
                msgs.insert(0, {"role": "system", "content": DEFAULT_SYSTEM_PROMPT})
            if len(msgs) >= 3 and any(m["role"] == "assistant" for m in msgs) and any(m["role"] == "user" for m in msgs):
                results.append({"messages": msgs})
                return results

    # 2. Direct system / user / assistant dictionary keys (e.g. CyberSec-Dataset)
    if "user" in item and "assistant" in item:
        u_text = str(item["user"]).strip()
        a_text = str(item["assistant"]).strip()
        s_text = str(item.get("system") or DEFAULT_SYSTEM_PROMPT).strip()
        if u_text and a_text:
            results.append({
                "messages": [
                    {"role": "system", "content": s_text},
                    {"role": "user", "content": u_text},
                    {"role": "assistant", "content": a_text}
                ]
            })
            return results

    # 3. ShareGPT format: "conversations"
    if "conversations" in item and isinstance(item["conversations"], list) and len(item["conversations"]) >= 2:
        msgs = []
        has_system = False
        for turn in item["conversations"]:
            if not isinstance(turn, dict):
                continue
            r_raw = turn.get("from") or turn.get("role") or turn.get("speaker") or ""
            c = turn.get("value") or turn.get("content") or turn.get("text") or ""
            r = normalize_role(r_raw)
            c = str(c).strip()
            if c:
                if r == "system":
                    has_system = True
                msgs.append({"role": r, "content": c})
        if msgs:
            if not has_system:
                msgs.insert(0, {"role": "system", "content": DEFAULT_SYSTEM_PROMPT})
            if len(msgs) >= 3 and any(m["role"] == "assistant" for m in msgs) and any(m["role"] == "user" for m in msgs):
                results.append({"messages": msgs})
                return results

    # 3. Instruction / Input / Output (or Prompt / Response / Completion)
    instruction = (
        item.get("instruction") or item.get("Instruction") or
        item.get("prompt") or item.get("Prompt") or
        item.get("question") or item.get("Question") or
        item.get("query") or item.get("Query") or ""
    )
    input_text = (
        item.get("input") or item.get("Input") or
        item.get("context") or item.get("Context") or
        item.get("code") or item.get("Code") or ""
    )
    output_text = (
        item.get("output") or item.get("Output") or
        item.get("response") or item.get("Response") or
        item.get("completion") or item.get("Completion") or
        item.get("answer") or item.get("Answer") or ""
    )
    
    if instruction and output_text:
        user_content = str(instruction).strip()
        if input_text and str(input_text).strip():
            user_content += f"\n\n```\n{str(input_text).strip()}\n```"
        
        results.append({
            "messages": [
                {"role": "system", "content": DEFAULT_SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
                {"role": "assistant", "content": str(output_text).strip()}
            ]
        })
        return results

    # 4. Code Vulnerability datasets (e.g. CyberSec-Dataset, code_train)
    code_field = item.get("code") or item.get("func") or item.get("vulnerable_code") or item.get("function") or ""
    fix_field = item.get("fixed_code") or item.get("fix") or item.get("patch") or item.get("remediation") or item.get("target") or ""
    cwe_field = item.get("cwe") or item.get("cwe_id") or item.get("flaw_type") or extract_cwe(str(item))
    flaw_field = item.get("flaw") or item.get("vulnerability") or item.get("description") or item.get("details") or ""
    lang_field = item.get("language") or item.get("lang") or "c"
    
    if code_field and (fix_field or flaw_field or cwe_field):
        rec = format_code_vulnerability_example(
            code=str(code_field),
            language=str(lang_field),
            cwe=str(cwe_field) if cwe_field else None,
            flaw=str(flaw_field) if flaw_field else None,
            details=item.get("details") or item.get("sink"),
            remediation=str(fix_field) if fix_field else None
        )
        if rec:
            results.append(rec)
            return results

    # 5. Nested objects / Knowledge base scenarios
    # Some domain JSONs have lists of "scenarios", "attacks", "vulnerabilities", "labs", "mitigations"
    for key in ("scenarios", "labs", "vulnerabilities", "attacks", "techniques", "examples", "records", "data"):
        if key in item and isinstance(item[key], list):
            for sub_item in item[key]:
                results.extend(process_raw_item(sub_item, source_name=source_name))
    
    # 6. If item has title/overview/attack_vector/remediation structure
    if "title" in item and ("attack" in item or "remediation" in item or "description" in item or "defense" in item):
        title = item.get("title", "Cybersecurity Scenario")
        desc = item.get("description") or item.get("overview") or ""
        attack = item.get("attack") or item.get("attack_vector") or item.get("exploitation") or ""
        defense = item.get("defense") or item.get("defense_strategy") or item.get("detection") or ""
        remediation = item.get("remediation") or item.get("mitigation") or item.get("fix") or ""
        
        user_prompt = f"Provide a comprehensive security analysis for: {title}"
        if desc:
            user_prompt += f"\n\n**Context / Description:**\n{desc}"
        
        assistant_resp = f"### Security Assessment: {title}\n"
        if attack:
            assistant_resp += f"\n#### Attack Vector & Threat Model\n{attack}\n"
        if defense:
            assistant_resp += f"\n#### Detection & Defense Strategy\n{defense}\n"
        if remediation:
            assistant_resp += f"\n#### Remediation & Secure Hardening\n{remediation}\n"
        
        results.append({
            "messages": [
                {"role": "system", "content": DEFAULT_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt.strip()},
                {"role": "assistant", "content": assistant_resp.strip()}
            ]
        })

    return results

def read_json_or_jsonl_stream(file_path: str) -> Generator[Dict[str, Any], None, None]:
    """Read a local file (.json, .jsonl, .gz) and yield items."""
    is_gz = file_path.endswith(".gz")
    opener = gzip.open if is_gz else open
    
    try:
        if file_path.endswith(".jsonl") or file_path.endswith(".jsonl.gz"):
            with opener(file_path, "rt", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            yield json.loads(line)
                        except json.JSONDecodeError:
                            continue
        elif file_path.endswith(".json") or file_path.endswith(".json.gz"):
            with opener(file_path, "rt", encoding="utf-8", errors="ignore") as f:
                try:
                    data = json.load(f)
                    if isinstance(data, list):
                        for el in data:
                            yield el
                    elif isinstance(data, dict):
                        yield data
                except json.JSONDecodeError:
                    # Fallback line-by-line if corrupted or concatenated JSON
                    f.seek(0)
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                yield json.loads(line)
                            except Exception:
                                pass
    except Exception as e:
        print(f"[Warning] Failed to read {file_path}: {e}", file=sys.stderr)

def fetch_hf_repo_files(hf_token: Optional[str] = None) -> List[str]:
    """List all JSON/JSONL files in Vyber07/cyber-security from Hugging Face API."""
    url = "https://huggingface.co/api/datasets/Vyber07/cyber-security"
    headers = {"User-Agent": "Mozilla/5.0"}
    if hf_token:
        headers["Authorization"] = f"Bearer {hf_token}"
    
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            siblings = data.get("siblings", [])
            valid_files = [
                s["rfilename"] for s in siblings
                if s["rfilename"].endswith((".json", ".jsonl", ".json.gz", ".jsonl.gz"))
                and not s["rfilename"].startswith(".")
            ]
            return valid_files
    except Exception as e:
        print(f"[Error] Failed to fetch Hugging Face file list: {e}", file=sys.stderr)
        return []

def download_hf_file(filename: str, output_path: str, hf_token: Optional[str] = None) -> bool:
    """Download a single file from the dataset repo."""
    url = f"https://huggingface.co/datasets/Vyber07/cyber-security/resolve/main/{filename}"
    headers = {"User-Agent": "Mozilla/5.0"}
    if hf_token:
        headers["Authorization"] = f"Bearer {hf_token}"
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as resp, open(output_path, "wb") as out_f:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                out_f.write(chunk)
        return True
    except urllib.error.HTTPError as e:
        if e.code == 401:
            print(f"[Error 401 Unauthorized] Access restricted for {filename}. Gated repository requires a Hugging Face token.", file=sys.stderr)
        else:
            print(f"[HTTP Error {e.code}] Failed downloading {filename}: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"[Error] Failed downloading {filename}: {e}", file=sys.stderr)
        return False

def clean_and_validate_record(record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Validate and clean record to strictly match Azure AI Foundry schema."""
    if not isinstance(record, dict) or "messages" not in record:
        return None
    
    msgs = record["messages"]
    if not isinstance(msgs, list) or len(msgs) < 2:
        return None
    
    cleaned_msgs = []
    for m in msgs:
        if not isinstance(m, dict) or "role" not in m or "content" not in m:
            return None
        role = normalize_role(m["role"])
        content = str(m["content"]).strip()
        if not content:
            return None
        cleaned_msgs.append({"role": role, "content": content})
    
    # Ensure system prompt is present
    if cleaned_msgs[0]["role"] != "system":
        cleaned_msgs.insert(0, {"role": "system", "content": DEFAULT_SYSTEM_PROMPT})
    
    # Check that alternating turns exist (user -> assistant)
    user_count = sum(1 for m in cleaned_msgs if m["role"] == "user")
    asst_count = sum(1 for m in cleaned_msgs if m["role"] == "assistant")
    if user_count == 0 or asst_count == 0:
        return None
    
    return {"messages": cleaned_msgs}

def convert_dataset(
    input_paths: List[str],
    train_output: str = "train.jsonl",
    val_output: str = "validation.jsonl",
    val_ratio: float = 0.2,
    max_samples: Optional[int] = None,
    seed: int = 42,
    hf_token: Optional[str] = None
) -> Tuple[int, int]:
    """Convert input files or HF dataset into train.jsonl and validation.jsonl."""
    all_records = []
    seen_hashes = set()
    
    for path in input_paths:
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for f in files:
                    if f.endswith((".json", ".jsonl", ".json.gz", ".jsonl.gz")) and not f.startswith("."):
                        full_p = os.path.join(root, f)
                        for raw_item in read_json_or_jsonl_stream(full_p):
                            for rec in process_raw_item(raw_item, source_name=f):
                                clean_rec = clean_and_validate_record(rec)
                                if clean_rec:
                                    # Deduplication hash on user content
                                    user_txt = next((m["content"] for m in clean_rec["messages"] if m["role"] == "user"), "")
                                    h = hash(user_txt[:200])
                                    if h not in seen_hashes:
                                        seen_hashes.add(h)
                                        all_records.append(clean_rec)
        elif os.path.isfile(path):
            for raw_item in read_json_or_jsonl_stream(path):
                for rec in process_raw_item(raw_item, source_name=os.path.basename(path)):
                    clean_rec = clean_and_validate_record(rec)
                    if clean_rec:
                        user_txt = next((m["content"] for m in clean_rec["messages"] if m["role"] == "user"), "")
                        h = hash(user_txt[:200])
                        if h not in seen_hashes:
                            seen_hashes.add(h)
                            all_records.append(clean_rec)
    
    if not all_records:
        print("[Warning] No valid records parsed from input paths.", file=sys.stderr)
        return (0, 0)
    
    random.seed(seed)
    random.shuffle(all_records)
    
    if max_samples and len(all_records) > max_samples:
        all_records = all_records[:max_samples]
    
    total = len(all_records)
    if val_ratio > 0 and total >= 2:
        val_size = max(1, int(round(total * val_ratio)))
        val_size = min(val_size, total - 1)  # ensure at least 1 train record
    else:
        val_size = int(total * val_ratio)
    val_records = all_records[:val_size]
    train_records = all_records[val_size:]
    
    # Write train.jsonl
    with open(train_output, "w", encoding="utf-8") as f:
        for rec in train_records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            
    # Write validation.jsonl
    with open(val_output, "w", encoding="utf-8") as f:
        for rec in val_records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            
    print(f"[Success] Processed {total} records:")
    print(f"  -> {train_output}: {len(train_records)} records ({((1 - val_ratio)*100):.0f}%)")
    print(f"  -> {val_output}: {len(val_records)} records ({(val_ratio*100):.0f}%)")
    
    return len(train_records), len(val_records)

def get_hf_token(provided_token: Optional[str] = None) -> Optional[str]:
    """Retrieve Hugging Face token from args, env, HF cache, or local token files."""
    if provided_token:
        return provided_token.strip()
    
    # 1. Environment variables
    for env_var in ("HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "HUGGINGFACE_TOKEN"):
        val = os.environ.get(env_var)
        if val and val.strip():
            return val.strip()
            
    # 2. Standard Hugging Face cache location (~/.cache/huggingface/token)
    hf_cache_token = os.path.expanduser("~/.cache/huggingface/token")
    if os.path.exists(hf_cache_token):
        try:
            with open(hf_cache_token, "r", encoding="utf-8") as f:
                token = f.read().strip()
                if token:
                    return token
        except Exception:
            pass

    # 3. Local .hf_token, ~/hftoken, or .env file in workspace
    token_files = [
        os.path.expanduser("~/hftoken"),
        os.path.expanduser("~/hftoken.txt"),
        os.path.expanduser("~/.hftoken"),
        ".hf_token",
        "hf_token.txt",
        ".env"
    ]
    for local_file in token_files:
        if os.path.exists(local_file):
            try:
                with open(local_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("HF_TOKEN="):
                            return line.split("=", 1)[1].strip().strip("\"'")
                        elif line.startswith("hf_"):
                            return line
            except Exception:
                pass
                
    return None

def main():
    parser = argparse.ArgumentParser(description="Convert cybersecurity datasets to Azure AI Foundry JSONL for Phi-4.")
    parser.add_argument("--input", "-i", nargs="+", help="Input files or directories containing JSON/JSONL files.")
    parser.add_argument("--hf-token", help="Hugging Face User Access Token for downloading gated dataset files.")
    parser.add_argument("--download-hf", action="store_true", help="Download from Hugging Face dataset Vyber07/cyber-security.")
    parser.add_argument("--max-hf-files", type=int, default=20, help="Max files to download from HF (default 20 for fast turnaround).")
    parser.add_argument("--train-out", default="train.jsonl", help="Output train JSONL file path (default: train.jsonl)")
    parser.add_argument("--val-out", default="validation.jsonl", help="Output validation JSONL file path (default: validation.jsonl)")
    parser.add_argument("--val-ratio", type=float, default=0.2, help="Validation set split ratio (default: 0.2)")
    parser.add_argument("--max-samples", type=int, default=None, help="Optional maximum samples to keep.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for deterministic split.")
    
    args = parser.parse_args()
    hf_token = get_hf_token(args.hf_token)
    
    input_paths = args.input or []
    
    if args.download_hf:
        print("[Info] Querying files from Vyber07/cyber-security...")
        files = fetch_hf_repo_files(hf_token=hf_token)
        if not files:
            print("[Error] No files could be listed from Hugging Face.", file=sys.stderr)
            if not hf_token:
                print("Tip: Pass --hf-token <YOUR_HF_TOKEN> or set HF_TOKEN environment variable.", file=sys.stderr)
        else:
            print(f"[Info] Found {len(files)} dataset files on Hugging Face.")
            download_dir = "hf_downloaded_data"
            os.makedirs(download_dir, exist_ok=True)
            to_download = files[:args.max_hf_files]
            success_count = 0
            for idx, rfile in enumerate(to_download, start=1):
                out_p = os.path.join(download_dir, rfile)
                print(f"[{idx}/{len(to_download)}] Downloading {rfile}...")
                if download_hf_file(rfile, out_p, hf_token=hf_token):
                    success_count += 1
            print(f"[Info] Successfully downloaded {success_count}/{len(to_download)} files.")
            if success_count > 0:
                input_paths.append(download_dir)
                
    if not input_paths:
        print("[Info] No input paths provided. Use --input <path> or --download-hf --hf-token <token>.")
        sys.exit(0)
        
    convert_dataset(
        input_paths=input_paths,
        train_output=args.train_out,
        val_output=args.val_out,
        val_ratio=args.val_ratio,
        max_samples=args.max_samples,
        seed=args.seed,
        hf_token=hf_token
    )

if __name__ == "__main__":
    main()
