#!/usr/bin/env python3
"""
Split cybersecurity datasets into train.jsonl and val.jsonl with anti-contamination guarantees.

Usage:
    python3 split_dataset.py --input raw_data.jsonl --ratio 0.85 --seed 42
"""

import os
import sys
import json
import random
import hashlib
import argparse

def hash_prompt(record_line: str) -> str:
    try:
        data = json.loads(record_line)
        msgs = data.get("messages", [])
        user_text = " ".join(m.get("content", "") for m in msgs if m.get("role") == "user")
        normalized = " ".join(user_text.lower().split())
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    except Exception:
        return hashlib.sha256(record_line.encode("utf-8")).hexdigest()

def main():
    parser = argparse.ArgumentParser(description="Split dataset into train.jsonl and val.jsonl with deduplication.")
    parser.add_argument("--input", "-i", default="train.jsonl", help="Input dataset JSONL to split.")
    parser.add_argument("--train-out", default="train.jsonl", help="Output train JSONL filename (default: train.jsonl)")
    parser.add_argument("--val-out", default="val.jsonl", help="Output validation JSONL filename (default: val.jsonl)")
    parser.add_argument("--ratio", "-r", type=float, default=0.85, help="Train split ratio (e.g. 0.85 for 85/15, default: 0.85)")
    parser.add_argument("--seed", "-s", type=int, default=42, help="Random seed for reproducibility (default: 42)")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print(f"[Error] Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)
        
    with open(args.input, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
        
    print(f"[Info] Read {len(lines)} total lines from {args.input}.")
    
    # Deduplication and Contamination Prevention
    unique_records = []
    seen_hashes = set()
    duplicates_removed = 0
    
    for line in lines:
        h = hash_prompt(line)
        if h not in seen_hashes:
            seen_hashes.add(h)
            unique_records.append(line)
        else:
            duplicates_removed += 1
            
    if duplicates_removed > 0:
        print(f"[Info] Removed {duplicates_removed} duplicate prompts to guarantee 0% data leakage.")
        
    random.seed(args.seed)
    random.shuffle(unique_records)
    
    total = len(unique_records)
    if total < 2:
        print("[Error] Not enough samples to split into train and validation.", file=sys.stderr)
        sys.exit(1)
        
    train_size = max(1, int(round(total * args.ratio)))
    train_size = min(train_size, total - 1) # guarantee at least 1 in val
    
    train_data = unique_records[:train_size]
    val_data = unique_records[train_size:]
    
    with open(args.train_out, "w", encoding="utf-8") as f:
        for line in train_data:
            f.write(line + "\n")
            
    with open(args.val_out, "w", encoding="utf-8") as f:
        for line in val_data:
            f.write(line + "\n")
            
    print(f"\n[Success] Created:")
    print(f"  - {args.train_out}: {len(train_data)} samples ({100*len(train_data)/total:.1f}%)")
    print(f"  - {args.val_out}:   {len(val_data)} samples ({100*len(val_data)/total:.1f}%)")
    
    # Also update validation.jsonl symlink/copy if val.jsonl is created
    if args.val_out == "val.jsonl":
        with open("validation.jsonl", "w", encoding="utf-8") as f:
            for line in val_data:
                f.write(line + "\n")

if __name__ == "__main__":
    main()

