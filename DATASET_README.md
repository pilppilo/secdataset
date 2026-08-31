---
license: apache-2.0
task_categories:
- text-generation
- question-answering
language:
- en
tags:
- cybersecurity
- penetration-testing
- red-team
- blue-team
- web-security
- cloud-security
- malware
- forensics
- exploit
- vulnerability
- iot
- ai-security
- bug-bounty
- offensive-security
- defensive-security
size_categories:
- 10B<n<100B
---

# Cybersecurity AI Knowledge Base — PhD-Level Dataset

## Overview

This is the most comprehensive cybersecurity knowledge base ever assembled for AI training. It covers **all domains** of cybersecurity at **PhD-level depth** — from offensive red teaming and bug bounty exploitation to defensive SOC operations, digital forensics, and cutting-edge AI/LLM security.

**Size:** 16 GB | **Files:** 507 | **Domains:** 30+ | **Sources:** 15+ platforms

## Purpose

- Train the world's most capable cybersecurity AI assistant
- Cover every domain: offensive, defensive, forensics, compliance, AI security
- Include real-world attack/defend/detect/analyze methodologies
- Provide hands-on lab scenarios from HackTheBox, TryHackMe, PortSwigger, VulnHub
- Reference MITRE ATT&CK, OWASP, NIST, CIS frameworks
- No restrictions — full offensive and defensive coverage for security research

---

## Domains & Coverage

### Offensive Security

| Domain | Files | Description |
|--------|-------|-------------|
| `red-team/` | 8 | Complete red team playbook — MITRE ATT&CK (200+ techniques, 400+ sub-techniques), adversary emulation, C2 frameworks, evasion techniques |
| `vapt/` | 5 | Vulnerability assessment, OWASP Testing Guide v4.2, PTES methodology, NIST SP 800-115 |
| `osint/` | 3 | Reconnaissance, information gathering, Shodan, Censys, Maltego, social media intelligence |
| `social-engineering/` | 3 | Phishing campaigns, pretexting, physical security, vishing, BEC attacks |
| `offensive-security/` | 1 | PhD-level offensive security reference — all attack phases, MITRE ATT&CK mapping |
| `penetration-testing/` | 1 | PTES, OWASP, NIST, OSSTMM methodologies, all testing types (black/white/grey box), certifications (OSCP, OSEP, OSWE, GPEN) |

### Web Security (PortSwigger Academy — All 31 Topics)

| Domain | Files | Description |
|--------|-------|-------------|
| `web-security/` | 1 | PhD-level reference covering all 31 PortSwigger topics: SQL injection (16 labs), XSS (30 labs), CSRF (8 labs), XXE (9 labs), SSRF, HTTP request smuggling (CL.TE, TE.CL, TE.TE, H2 variants, client-side desync), SSTI, insecure deserialization, authentication, OAuth 2.0, access control/IDOR, path traversal, OS command injection, JWT attacks, web cache poisoning, prototype pollution, GraphQL, race conditions, NoSQL injection, API testing, web LLM attacks, web cache deception |

### Bug Bounty & Vulnerability Disclosure

| Domain | Files | Description |
|--------|-------|-------------|
| `bug-bounty/` | 1 | HackerOne (600K+ bugs, 210% AI vuln increase in 2025), BugCrowd (7x more critical vulns), all vulnerability categories, program types, industry verticals |

### Labs & Hands-On Scenarios

| Domain | Files | Description |
|--------|-------|-------------|
| `labs-scenarios/` | 1 | HackTheBox (1500+ labs), TryHackMe, PortSwigger (100+ labs), VulnHub (12+ pages of VMs), pwn.guide (200+ tutorials), PwnTillDawn — all difficulty levels from beginner to expert |

### Defensive Security & Blue Team

| Domain | Files | Description |
|--------|-------|-------------|
| `blue-team/` | 5 | SOC operations (Tier 1-3), detection engineering, threat hunting, YARA, Sigma, Snort, Suricata |
| `defensive-security/` | 1 | PhD-level defensive reference — NIST CSF (108 subcategories), MITRE D3FEND (100+ techniques), CIS Controls v8 (153 safeguards) |
| `digital-forensics/` | 3 | Memory forensics (Volatility), disk forensics (Autopsy), network forensics (Wireshark, Zeek), mobile forensics |
| `cyber-defense/` | 3 | SOC operations, incident response playbooks, threat detection |
| `compliance/` | 3 | ISO 27001, SOC 2, PCI DSS, HIPAA, GDPR, FedRAMP, NIST 800-53, CIS Benchmarks |

### Network & Infrastructure

| Domain | Files | Description |
|--------|-------|-------------|
| `network-security/` | 5 | Firewalls, IDS/IPS, traffic analysis, network attacks (ARP spoofing, DNS spoofing, DHCP spoofing, SSL stripping), APT detection |
| `cloud-security/` | 2 | AWS, Azure, GCP security — IAM attacks, data exposure, compute attacks, serverless exploitation, Kubernetes compromise |
| `container-security/` | 3 | Docker, Kubernetes, container escape, image scanning, runtime security |

### Application Security

| Domain | Files | Description |
|--------|-------|-------------|
| `api-security/` | 3 | REST, GraphQL, JWT attacks, API testing, OWASP API Security Top 10 |
| `blockchain-security/` | 4 | Smart contracts, DeFi, Web3 security, flash loan attacks, reentrancy |
| `devsecops/` | 3 | CI/CD security, SAST/DAST, pipeline hardening, Infrastructure as Code |

### Threat Analysis

| Domain | Files | Description |
|--------|-------|-------------|
| `malware/` | 4 | Malware analysis, reverse engineering, detection, YARA rules, sandbox analysis |
| `phishing/` | 4 | Email phishing, spear phishing, whaling, BEC, AI-generated phishing, deepfake attacks |
| `ransomware/` | 3 | Ransomware families (LockBit, ALPHV, Cl0p), double/triple extortion, RaaS, incident response |
| `botnet-ddos/` | 3 | Botnet analysis, DDoS mitigation, traffic analysis, Mirai, Mozi |

### Specialized Domains

| Domain | Files | Description |
|--------|-------|-------------|
| `iot-openthread-security/` | 8 | **Thread protocol** (IEEE 802.15.4), **OpenThread** architecture, **Matter** protocol, mesh networking attacks/defense, commissioning exploitation, border router attacks, cryptographic key management, forensics, red team playbook, security testing lab |
| `ai-ml-security/` | 4 | Adversarial ML, model security, data poisoning, OWASP LLM Top 10, OWASP ML Top 10, MITRE ATLAS (50+ techniques) |
| `ai-security/` | 1 | PhD-level AI security — prompt injection, training data poisoning, model extraction, web LLM attacks |
| `mobile-security/` | 3 | Android/iOS security, mobile app testing, reverse engineering |
| `identity-access-management/` | 3 | IAM, RBAC, SSO, PAM, Active Directory attacks |
| `supply-chain-security/` | 3 | Dependency scanning, SBOM, CI/CD security, software supply chain attacks |
| `cryptography/` | 5 | Encryption algorithms, key management, TLS/SSL, cryptographic attacks, post-quantum crypto |
| `reverse-engineering/` | 3 | Binary analysis, firmware RE, malware RE, IDA Pro, Ghidra |
| `security-code/` | 2 | Secure coding practices, code review, vulnerability patterns |
| `cybersecurity-knowledge-expansion/` | 20 | Cross-domain knowledge expansion datasets |
| `security-research/` | 1 | PhD-level research — PortSwigger Research (James Kettle, Gareth Heyes), SANS 2026 white papers, novel attack techniques |

---

## Data Formats

### ShareGPT Format
```json
{
  "conversations": [
    {"from": "system", "value": "You are a cybersecurity expert..."},
    {"from": "human", "value": "How do I exploit SQL injection?"},
    {"from": "gpt", "value": "## SQL Injection Exploitation..."}
  ]
}
```

### Instruction/IO Format
```json
{
  "Instruction": "Explain SSRF attack techniques",
  "Input": "Web application with internal API access",
  "Output": "## SSRF Attack Techniques...",
  "Metadata": {
    "domain": "web-security",
    "attack_types": ["ssrf", "blacklist_bypass", "whitelist_bypass"],
    "defense_types": ["input_validation", "network_segmentation"],
    "tools": ["burpsuite", "curl", "ssrfmap"]
  }
}
```

### PhD-Level Reference Format
```json
{
  "metadata": {
    "domain": "web-security",
    "subdomain": "phd-level-comprehensive",
    "source": "PortSwigger Web Security Academy",
    "level": "PhD",
    "difficulty": "expert",
    "task_type": "phd_level_reference"
  }
}
```

---

## Record Structure

Each record includes a combination of:

- **Attack Vectors** — How to perform attacks step-by-step
- **Defense Strategies** — How to prevent and detect attacks
- **Detection Methods** — YARA rules, Sigma rules, Snort/Suricata rules, KQL queries
- **Forensic Analysis** — How to investigate after an incident
- **Tools & Techniques** — Specific tools with commands and examples
- **Real-World Scenarios** — Based on actual CVEs, breaches, and CTF challenges
- **Remediation** — How to fix vulnerabilities
- **References** — Links to frameworks, standards, and research

---

## Sources & Platforms

### Vulnerability Intelligence
- **NVD** (National Vulnerability Database)
- **MITRE ATT&CK** Framework (200+ techniques, 400+ sub-techniques)
- **CISA** Known Exploited Vulnerabilities
- **OSV** (Open Source Vulnerabilities)
- **GitHub Advisory Database**

### Offensive Security Platforms
- **HackTheBox** — 1500+ hands-on labs, red/blue/purple team tracks
- **TryHackMe** — Learning paths, rooms, challenges
- **PortSwigger Web Security Academy** — 31 topics, 100+ labs
- **VulnHub** — 12+ pages of vulnerable VMs
- **pwn.guide** — 200+ tutorials (web, wireless, hardware, blue team)
- **PwnTillDawn** — Online battlefield

### Bug Bounty Platforms
- **HackerOne** — 600K+ bugs found, 210% AI vulnerability increase in 2025
- **BugCrowd** — Bug bounty, VDP, pentest as a service, red team as a service

### Security Research
- **PortSwigger Research** — James Kettle, Gareth Heyes, Zakhar Fedotkin
- **SANS Institute** — 2026 white papers on AI security, threat intelligence, Kubernetes
- **OWASP** — Top 10 2021, API Security Top 10, LLM Top 10, ML Top 10

### Frameworks & Standards
- **NIST Cybersecurity Framework** (108 subcategories)
- **MITRE D3FEND** (100+ defensive techniques)
- **MITRE ATLAS** (50+ AI/ML attack techniques)
- **CIS Controls v8** (153 safeguards)
- **ISO 27001**, **SOC 2**, **PCI DSS**, **HIPAA**, **GDPR**, **FedRAMP**

### IoT & Embedded Security
- **OpenThread** (openthread.io) — Thread protocol implementation
- **Thread Group** — Thread specification, Matter protocol
- **IEEE 802.15.4** — Low-power wireless mesh networking

---

## Statistics

| Metric | Value |
|--------|-------|
| Total Files | 507 |
| Total Size | 16 GB |
| Domain Folders | 30+ |
| PhD-Level Datasets | 8 |
| Valid JSON Files | 394 |
| Sources/Platforms | 15+ |
| MITRE ATT&CK Techniques | 200+ |
| PortSwigger Topics | 31 |
| HackTheBox Labs | 1500+ |
| HackerOne Bugs Referenced | 600K+ |
| OWASP Top 10 Versions | 4 (Web, API, LLM, ML) |

---

## Usage

This dataset is designed for:

1. **Fine-tuning cybersecurity AI models** — LLMs for security assistance
2. **Training security professionals** — Red team, blue team, purple team
3. **Building security automation tools** — SOAR, SIEM, detection engineering
4. **Security education and research** — University courses, certifications
5. **Red/blue team exercises** — Tabletop exercises, live-fire simulations
6. **Bug bounty preparation** — HackerOne, BugCrowd methodology
7. **Certification study** — OSCP, OSEP, OSWE, GPEN, CISSP, CEH
8. **Compliance preparation** — ISO 27001, SOC 2, PCI DSS, HIPAA, GDPR

---

## License

Apache 2.0

---

## Links

- **HuggingFace:** https://huggingface.co/datasets/Vyber07/cyber-security
- **GitHub:** https://github.com/Vyber07/