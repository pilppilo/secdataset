#!/usr/bin/env python3
"""
Azure AI Foundry & Cybersecurity Dataset Validator for Phi-4 / Phi-3.5 / Ministral-3B.

Performs strict validation checks:
1. Azure AI Foundry JSONL Syntax & Schema:
   - Every line is an independent single-line JSON object.
   - Top-level object contains "messages" array.
   - Strict role names ("system", "user", "assistant").
   - Valid turn sequence (starts with system/user, ends with assistant).
   - Non-empty content strings across all messages.

2. Train / Validation Split & Leakage Checks:
   - Cross-file data leakage / contamination detection (hashes user queries & code).
   - Split ratio verification (recommended 80/20 or 85/15).
   - Sample size guidelines (minimum 50-100 to test, 1,000+ for domain adaptation).
   - CWE distribution coverage across train and validation sets.

3. Cybersecurity & SAST Quality Checks:
   - Structured reasoning format (CWE ID, Root Cause / Taint analysis, Remediation).
   - Markdown code block fence integrity (matching ``` fences).
   - Token length estimations and context window compliance.
"""

import os
import sys
import json
import hashlib
import re
import argparse
from collections import Counter
from typing import Dict, Any, List, Set, Tuple, Optional

CWE_PATTERN = re.compile(r"CWE[-_ ](\d+)", re.IGNORECASE)

def estimate_tokens(text: str) -> int:
    """Rough token estimation for Phi-4 / LLaMA / Mistral tokenizers (~3.8 chars/token)."""
    return max(1, int(len(text) / 3.8))

def hash_content(text: str) -> str:
    """Compute normalized SHA256 hash for contamination detection."""
    normalized = " ".join(text.lower().split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

def check_code_fences(text: str) -> bool:
    """Check if markdown triple backticks are properly paired."""
    fences = text.count("```")
    return fences % 2 == 0

def validate_single_file(file_path: str) -> Dict[str, Any]:
    print(f"\n-------------------------------------------------------")
    print(f"Checking File: {file_path}")
    print(f"-------------------------------------------------------")
    
    total_lines = 0
    passed_records = 0
    errors = []
    warnings = []
    
    role_counters = Counter()
    cwe_counter = Counter()
    total_tokens = 0
    token_lengths = []
    
    records = []
    prompt_hashes = {}
    
    has_structured_reasoning_count = 0
    unbalanced_fences_count = 0
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line_idx, line in enumerate(f, start=1):
                total_lines += 1
                raw_line = line.strip()
                
                if not raw_line:
                    errors.append(f"Line {line_idx}: Disallowed empty line in JSONL.")
                    continue
                
                # 1. Single-line JSON syntax check
                try:
                    record = json.loads(raw_line)
                except json.JSONDecodeError as e:
                    errors.append(f"Line {line_idx}: Invalid JSON syntax - {e}")
                    continue
                
                if not isinstance(record, dict):
                    errors.append(f"Line {line_idx}: Top-level item must be a JSON object, got {type(record).__name__}.")
                    continue
                
                # 2. Schema check: "messages"
                if "messages" not in record:
                    errors.append(f"Line {line_idx}: Missing required 'messages' key.")
                    continue
                
                messages = record["messages"]
                if not isinstance(messages, list):
                    errors.append(f"Line {line_idx}: 'messages' must be a list, got {type(messages).__name__}.")
                    continue
                
                if len(messages) < 2:
                    errors.append(f"Line {line_idx}: 'messages' must have at least 2 entries (user and assistant), got {len(messages)}.")
                    continue
                
                # 3. Roles and turn validation
                line_valid = True
                has_system = False
                has_user = False
                has_assistant = False
                record_text = ""
                user_prompts = []
                assistant_responses = []
                
                for msg_idx, msg in enumerate(messages):
                    if not isinstance(msg, dict):
                        errors.append(f"Line {line_idx}, message [{msg_idx}]: entry must be a JSON object.")
                        line_valid = False
                        break
                    
                    if "role" not in msg or "content" not in msg:
                        errors.append(f"Line {line_idx}, message [{msg_idx}]: missing 'role' or 'content' key.")
                        line_valid = False
                        break
                    
                    role = msg["role"]
                    content = msg["content"]
                    
                    if not isinstance(role, str) or role not in ("system", "user", "assistant"):
                        errors.append(f"Line {line_idx}, message [{msg_idx}]: role must be 'system', 'user', or 'assistant', got '{role}'.")
                        line_valid = False
                        break
                    
                    if not isinstance(content, str) or not content.strip():
                        errors.append(f"Line {line_idx}, message [{msg_idx}]: content must be a non-empty string.")
                        line_valid = False
                        break
                    
                    role_counters[role] += 1
                    record_text += " " + content
                    
                    if role == "system":
                        has_system = True
                        if msg_idx != 0:
                            errors.append(f"Line {line_idx}, message [{msg_idx}]: 'system' role must be at index 0.")
                            line_valid = False
                            break
                    elif role == "user":
                        has_user = True
                        user_prompts.append(content)
                    elif role == "assistant":
                        has_assistant = True
                        assistant_responses.append(content)
                
                if not line_valid:
                    continue
                
                if not (has_user and has_assistant):
                    errors.append(f"Line {line_idx}: Record must contain at least one 'user' and one 'assistant' message.")
                    continue
                
                if messages[-1]["role"] != "assistant":
                    errors.append(f"Line {line_idx}: Last turn must be 'assistant', got '{messages[-1]['role']}'.")
                    continue
                
                # Check markdown code fences
                for c in user_prompts + assistant_responses:
                    if not check_code_fences(c):
                        unbalanced_fences_count += 1
                        warnings.append(f"Line {line_idx}: Unbalanced markdown code fence (```) detected.")
                        break
                
                # Check structured reasoning quality
                asst_full = " ".join(assistant_responses)
                if any(k in asst_full.lower() for k in ("cwe", "vulnerability", "root cause", "remediation", "fix", "sink", "source")):
                    has_structured_reasoning_count += 1
                
                # CWE tracking
                found_cwes = set(CWE_PATTERN.findall(record_text))
                for c in found_cwes:
                    cwe_counter[f"CWE-{c}"] += 1
                
                # Token estimation
                est_tok = estimate_tokens(record_text)
                total_tokens += est_tok
                token_lengths.append(est_tok)
                
                # Hash for deduplication / leakage detection
                user_combined = " ".join(user_prompts)
                h = hash_content(user_combined)
                if h in prompt_hashes:
                    warnings.append(f"Line {line_idx}: Duplicate user prompt (matches line {prompt_hashes[h]}).")
                else:
                    prompt_hashes[h] = line_idx
                
                records.append({
                    "line": line_idx,
                    "tokens": est_tok,
                    "cwes": found_cwes,
                    "prompt_hash": h,
                    "raw": record
                })
                passed_records += 1

    except FileNotFoundError:
        print(f"[Error] File not found: {file_path}", file=sys.stderr)
        return {"success": False, "passed": 0, "total": 0, "errors": [f"File not found: {file_path}"]}
    except Exception as e:
        print(f"[Error] Exception reading {file_path}: {e}", file=sys.stderr)
        return {"success": False, "passed": 0, "total": 0, "errors": [str(e)]}

    # Summary Statistics
    print(f"Lines Checked:         {total_lines}")
    print(f"Passed Azure Schema:   {passed_records} ({100 * passed_records / max(1, total_lines):.1f}%)")
    print(f"Role Counts:           System: {role_counters['system']} | User: {role_counters['user']} | Assistant: {role_counters['assistant']}")
    
    if token_lengths:
        avg_tok = total_tokens / len(token_lengths)
        print(f"Token Stats (Est.):    Avg: {avg_tok:.0f} | Min: {min(token_lengths)} | Max: {max(token_lengths)} | Total: {total_tokens:,}")
        if max(token_lengths) > 16384:
            warnings.append(f"Max tokens ({max(token_lengths)}) exceeds standard 16k context window.")
    
    reasoning_pct = (100 * has_structured_reasoning_count / max(1, passed_records))
    print(f"Security Reasoning:    {has_structured_reasoning_count}/{passed_records} ({reasoning_pct:.1f}%) assistant responses have structured security reasoning.")
    
    if cwe_counter:
        print(f"Top CWE Classes:       {', '.join([f'{k} ({v})' for k, v in cwe_counter.most_common(6)])}")
        
    if errors:
        print(f"\n[Validation Status: FAILED] Found {len(errors)} error(s):")
        for err in errors[:8]:
            print(f"  - {err}")
        if len(errors) > 8:
            print(f"  ... and {len(errors)-8} more errors.")
        return {
            "success": False,
            "passed": passed_records,
            "total": total_lines,
            "errors": errors,
            "warnings": warnings,
            "records": records,
            "cwe_counter": cwe_counter,
            "prompt_hashes": prompt_hashes
        }
    else:
        print(f"\n[Validation Status: PASSED] 100% Azure AI Foundry compliant.")
        if warnings:
            print(f"Note: {len(warnings)} warning(s) observed (e.g. duplicate prompts or markdown formatting).")
        return {
            "success": True,
            "passed": passed_records,
            "total": total_lines,
            "errors": [],
            "warnings": warnings,
            "records": records,
            "cwe_counter": cwe_counter,
            "prompt_hashes": prompt_hashes
        }

def validate_train_val_split(train_res: Dict[str, Any], val_res: Dict[str, Any], train_name: str, val_name: str) -> bool:
    print(f"\n=======================================================")
    print(f"Cross-Validation: Train/Validation Split Analysis")
    print(f"=======================================================")
    
    train_count = train_res["passed"]
    val_count = val_res["passed"]
    total_count = train_count + val_count
    
    if total_count == 0:
        print("[Error] No valid records to analyze between train and validation.", file=sys.stderr)
        return False
        
    train_pct = 100 * train_count / total_count
    val_pct = 100 * val_count / total_count
    print(f"Sample Distribution:   {train_name}: {train_count} ({train_pct:.1f}%) | {val_name}: {val_count} ({val_pct:.1f}%)")
    
    split_ok = True
    # 1. Check recommended split ratio (70/30 to 95/5)
    if val_pct < 5.0:
        print(f"  [Warning] Validation set is very small ({val_pct:.1f}%). Recommended: 10-20% to accurately monitor validation loss.")
    elif val_pct > 35.0:
        print(f"  [Warning] Validation set is large ({val_pct:.1f}%). Consider allocating more data to training (80-90%).")
    else:
        print(f"  [Split Check: OK] Ratio is well-balanced ({train_pct:.0f}% / {val_pct:.0f}%).")
        
    # 2. Check sample size recommendations
    if total_count < 50:
        print(f"  [Size Warning] Total samples ({total_count}) is below recommended minimum for fine-tuning pipeline tests (50-100).")
    elif total_count < 1000:
        print(f"  [Size Info] Dataset size ({total_count}) is suitable for fine-tuning pipeline testing. For full SAST domain adaptation, 1,000–5,000 samples is ideal.")
    else:
        print(f"  [Size Check: OK] Dataset size ({total_count:,} samples) is great for domain adaptation.")

    # 3. Data Contamination / Leakage Check
    train_hashes = train_res.get("prompt_hashes", {})
    val_hashes = val_res.get("prompt_hashes", {})
    leakage = set(train_hashes.keys()).intersection(set(val_hashes.keys()))
    
    if leakage:
        print(f"\n  [DATA LEAKAGE DETECTED] Found {len(leakage)} identical prompt(s) in BOTH {train_name} and {val_name}!")
        sample_leaks = list(leakage)[:5]
        for h in sample_leaks:
            print(f"    - Overlap: {train_name} line {train_hashes[h]} <=> {val_name} line {val_hashes[h]}")
        print("  [Fix] Remove duplicate prompts from validation set to prevent artificial metric inflation.")
        split_ok = False
    else:
        print(f"  [Leakage Check: PASSED] 0% Data Contamination! Zero prompt overlap between train and validation.")

    # 4. CWE Coverage Check
    train_cwes = set(train_res.get("cwe_counter", {}).keys())
    val_cwes = set(val_res.get("cwe_counter", {}).keys())
    if train_cwes and val_cwes:
        unseen_val_cwes = val_cwes - train_cwes
        overlap_cwes = train_cwes.intersection(val_cwes)
        print(f"  [CWE Distribution] {len(overlap_cwes)} shared CWE classes across train and val.")
        if unseen_val_cwes:
            print(f"  [CWE Info] {len(unseen_val_cwes)} CWE(s) in validation not present in training: {', '.join(list(unseen_val_cwes)[:5])}")

    return split_ok

def auto_detect_files(file_list: List[str]) -> Tuple[Optional[str], Optional[str], List[str]]:
    """Detect train, val/validation, or general files from arguments."""
    train_file = None
    val_file = None
    others = []
    
    for f in file_list:
        base = os.path.basename(f).lower()
        if "train" in base and not train_file:
            train_file = f
        elif ("val" in base or "test" in base) and not val_file:
            val_file = f
        else:
            others.append(f)
            
    return train_file, val_file, others

def main():
    parser = argparse.ArgumentParser(description="Validate Azure AI Foundry Phi-4 / Ministral fine-tuning datasets.")
    parser.add_argument("files", nargs="*", help="JSONL files to validate (e.g. train.jsonl val.jsonl)")
    parser.add_argument("--train", help="Explicit path to train.jsonl")
    parser.add_argument("--val", help="Explicit path to val.jsonl or validation.jsonl")
    args = parser.parse_args()
    
    all_files = list(args.files)
    train_path = args.train
    val_path = args.val
    
    if not train_path and not val_path and all_files:
        detected_train, detected_val, others = auto_detect_files(all_files)
        train_path = detected_train
        val_path = detected_val
        files_to_check = all_files
    else:
        files_to_check = []
        if train_path: files_to_check.append(train_path)
        if val_path: files_to_check.append(val_path)
        files_to_check.extend(all_files)
        files_to_check = list(dict.fromkeys(files_to_check)) # deduplicate
        
    if not files_to_check:
        # Default fallback to check current directory
        if os.path.exists("train.jsonl") and (os.path.exists("val.jsonl") or os.path.exists("validation.jsonl")):
            train_path = "train.jsonl"
            val_path = "val.jsonl" if os.path.exists("val.jsonl") else "validation.jsonl"
            files_to_check = [train_path, val_path]
        else:
            print("[Info] Usage: python3 validate_dataset.py train.jsonl val.jsonl")
            sys.exit(0)

    results = {}
    all_valid = True
    for f in files_to_check:
        res = validate_single_file(f)
        results[f] = res
        if not res["success"]:
            all_valid = False
            
    if train_path and val_path and train_path in results and val_path in results:
        split_ok = validate_train_val_split(results[train_path], results[val_path], train_path, val_path)
        if not split_ok:
            all_valid = False
            
    print(f"\n=======================================================")
    if all_valid:
        print(">> ALL VALIDATION CHECKS PASSED: READY FOR AZURE AI FOUNDRY <<")
        print("=======================================================\n")
        sys.exit(0)
    else:
        print(">> VALIDATION ISSUES DETECTED: PLEASE RESOLVE BEFORE SUBMITTING <<")
        print("=======================================================\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
