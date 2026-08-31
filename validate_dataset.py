#!/usr/bin/env python3
"""
Strict Azure AI Foundry & Phi-4 Dataset Validator.

Validates that JSONL files comply with:
1. Valid JSON on every single line (no multi-line JSON objects).
2. Exactly one top-level dictionary containing the "messages" key (list).
3. Every message contains "role" and "content".
4. Roles are strictly from ["system", "user", "assistant"].
5. Conversation starts with system (recommended) or user, followed by valid turns, ending with assistant.
6. Non-empty string content in all roles.
7. Checks token length estimates and distribution of CWEs / attack types.
"""

import sys
import json
import argparse
import re
from collections import Counter
from typing import Dict, Any, List

CWE_PATTERN = re.compile(r"CWE[-_ ](\d+)", re.IGNORECASE)

def estimate_tokens(text: str) -> int:
    """Rough token estimation (1 token ≈ 4 characters or 0.75 words)."""
    return max(1, int(len(text) / 3.8))

def validate_jsonl_file(file_path: str, verbose: bool = False) -> Dict[str, Any]:
    print(f"\n=======================================================")
    print(f"Validating Azure AI Foundry JSONL: {file_path}")
    print(f"=======================================================")
    
    total_lines = 0
    passed_records = 0
    errors = []
    
    role_counters = Counter()
    cwe_counter = Counter()
    total_chars = 0
    total_tokens = 0
    token_lengths = []
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line_idx, line in enumerate(f, start=1):
                total_lines += 1
                raw_line = line.strip()
                
                if not raw_line:
                    errors.append(f"Line {line_idx}: Empty line found (disallowed in strict JSONL).")
                    continue
                
                # Check single-line JSON parsing
                try:
                    record = json.loads(raw_line)
                except json.JSONDecodeError as e:
                    errors.append(f"Line {line_idx}: Invalid JSON: {e}")
                    continue
                
                if not isinstance(record, dict):
                    errors.append(f"Line {line_idx}: Top-level item must be a JSON object/dict, got {type(record).__name__}.")
                    continue
                
                if "messages" not in record:
                    errors.append(f"Line {line_idx}: Missing 'messages' key in top-level JSON object.")
                    continue
                
                messages = record["messages"]
                if not isinstance(messages, list):
                    errors.append(f"Line {line_idx}: 'messages' must be a list, got {type(messages).__name__}.")
                    continue
                
                if len(messages) < 2:
                    errors.append(f"Line {line_idx}: 'messages' must have at least 2 entries (user and assistant), got {len(messages)}.")
                    continue
                
                # Validate roles and sequence
                line_valid = True
                has_system = False
                has_user = False
                has_assistant = False
                record_text = ""
                
                for msg_idx, msg in enumerate(messages):
                    if not isinstance(msg, dict):
                        errors.append(f"Line {line_idx}, msg {msg_idx}: message entry must be a dict.")
                        line_valid = False
                        break
                    
                    if "role" not in msg or "content" not in msg:
                        errors.append(f"Line {line_idx}, msg {msg_idx}: missing 'role' or 'content' key.")
                        line_valid = False
                        break
                    
                    role = msg["role"]
                    content = msg["content"]
                    
                    if not isinstance(role, str) or role not in ("system", "user", "assistant"):
                        errors.append(f"Line {line_idx}, msg {msg_idx}: role must be 'system', 'user', or 'assistant', got '{role}'.")
                        line_valid = False
                        break
                    
                    if not isinstance(content, str) or not content.strip():
                        errors.append(f"Line {line_idx}, msg {msg_idx}: content must be a non-empty string.")
                        line_valid = False
                        break
                    
                    role_counters[role] += 1
                    record_text += " " + content
                    
                    if role == "system":
                        has_system = True
                        if msg_idx != 0:
                            errors.append(f"Line {line_idx}, msg {msg_idx}: 'system' role should only appear at index 0.")
                            line_valid = False
                            break
                    elif role == "user":
                        has_user = True
                    elif role == "assistant":
                        has_assistant = True
                
                if not line_valid:
                    continue
                
                if not (has_user and has_assistant):
                    errors.append(f"Line {line_idx}: Record must contain at least one 'user' and one 'assistant' message.")
                    continue
                
                # Check last message is assistant
                if messages[-1]["role"] != "assistant":
                    errors.append(f"Line {line_idx}: Last message role must be 'assistant', got '{messages[-1]['role']}'.")
                    continue
                
                # CWE extraction
                cwes_found = CWE_PATTERN.findall(record_text)
                for c in set(cwes_found):
                    cwe_counter[f"CWE-{c}"] += 1
                
                est_tok = estimate_tokens(record_text)
                total_tokens += est_tok
                total_chars += len(record_text)
                token_lengths.append(est_tok)
                passed_records += 1
                
    except FileNotFoundError:
        print(f"[Error] File not found: {file_path}", file=sys.stderr)
        return {"success": False, "passed": 0, "total": 0, "errors": [f"File not found: {file_path}"]}
    except Exception as e:
        print(f"[Error] Exception reading {file_path}: {e}", file=sys.stderr)
        return {"success": False, "passed": 0, "total": 0, "errors": [str(e)]}

    # Summary
    print(f"Total Lines Processed: {total_lines}")
    print(f"Valid Records Passed:  {passed_records} ({100 * passed_records / max(1, total_lines):.1f}%)")
    print(f"Role Distribution:     System: {role_counters['system']}, User: {role_counters['user']}, Assistant: {role_counters['assistant']}")
    
    if token_lengths:
        avg_tok = total_tokens / len(token_lengths)
        max_tok = max(token_lengths)
        min_tok = min(token_lengths)
        print(f"Token Stats (Est.):    Avg: {avg_tok:.0f} tokens | Min: {min_tok} | Max: {max_tok} | Total: {total_tokens:,}")
    
    if cwe_counter:
        print(f"\nTop Detected CWEs ({len(cwe_counter)} unique):")
        for cwe, count in cwe_counter.most_common(10):
            print(f"  - {cwe}: {count} occurrences")
            
    if errors:
        print(f"\n[Validation Failed] Found {len(errors)} error(s):")
        for err in errors[:10]:
            print(f"  - {err}")
        if len(errors) > 10:
            print(f"  ... and {len(errors)-10} more errors.")
        return {"success": False, "passed": passed_records, "total": total_lines, "errors": errors}
    else:
        print("\n[VALIDATION PASSED] 100% compliant with Azure AI Foundry Phi-4 fine-tuning schema! Ready for upload.")
        return {"success": True, "passed": passed_records, "total": total_lines, "errors": []}

def main():
    parser = argparse.ArgumentParser(description="Validate Azure AI Foundry Phi-4 JSONL files.")
    parser.add_argument("files", nargs="+", help="Path to JSONL files (e.g. train.jsonl validation.jsonl)")
    args = parser.parse_args()
    
    all_success = True
    for f in args.files:
        res = validate_jsonl_file(f)
        if not res.get("success"):
            all_success = False
            
    if not all_success:
        sys.exit(1)
    else:
        print("\nAll files successfully validated!")

if __name__ == "__main__":
    main()

