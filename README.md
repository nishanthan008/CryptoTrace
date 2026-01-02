# CryptoTrace

**CLI-based security testing tool for identifying exposed cryptographic materials in web applications**

## ⚠️ Legal Notice

**AUTHORIZED USE ONLY**

This tool is designed exclusively for authorized security testing scenarios including:
- Application security testing
- Penetration testing (with proper authorization)
- Secure code review validation
- Client-side encryption misuse detection
- CI/CD security validation

**Unauthorized use of this tool may be illegal.** Always obtain explicit written permission before testing any application you do not own.

## 🎯 Features

- **Cryptographic Material Detection**
  - Hardcoded encryption keys
  - Initialization Vectors (IVs)
  - Weak or insecure client-side cryptographic usage
  - Algorithm and mode identification

- **Runtime Observation**
  - Web Crypto API monitoring
  - CryptoJS library usage detection
  - Node-forge library detection
  - Custom crypto implementation analysis

- **Comprehensive Reporting**
  - JSON (machine-readable)
  - SARIF (CI/CD integration)
  - Markdown (human-readable)
  - Automatic secret redaction

- **Security Controls**
  - Mandatory authorization flag
  - Default secret masking
  - Local-only execution
  - Audit logging

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/cryptotrace.git
cd cryptotrace

# Install dependencies
pip install -r requirements.txt

# Install Playwright browsers
playwright install chromium

# Install the package
pip install -e .
```

## 🚀 Usage

### Basic Scan

```bash
cryptotrace scan --url https://example.com --authorized
```

### Advanced Options

```bash
cryptotrace scan \
  --url https://example.com \
  --authorized \
  --auth auth.json \
  --headless \
  --capture-network \
  --capture-runtime \
  --detect-keys \
  --detect-iv \
  --detect-algorithms \
  --timeout 300 \
  --report json \
  --output report.json
```

### CLI Options

| Option | Description | Required |
|--------|-------------|----------|
| `--url <url>` | Target application URL | ✅ |
| `--authorized` | Explicit authorization acknowledgment | ✅ |
| `--auth <file>` | Authentication context (JSON file) | ❌ |
| `--runtime <type>` | Runtime type (web/webview/api) | ❌ |
| `--headless` | Run browser in headless mode | ❌ |
| `--capture-network` | Capture HTTP/HTTPS traffic | ❌ |
| `--capture-runtime` | Observe crypto functions at runtime | ❌ |
| `--detect-keys` | Detect encryption/decryption keys | ❌ |
| `--detect-iv` | Detect IV usage | ❌ |
| `--detect-algorithms` | Identify algorithms & modes | ❌ |
| `--timeout <seconds>` | Scan timeout (default: 300) | ❌ |
| `--report <format>` | Output format (json/sarif/markdown) | ❌ |
| `--output <file>` | Save report to file | ❌ |
| `--no-redact-secrets` | Disable secret masking | ❌ |

### Authentication File Format

```json
{
  "cookies": [
    {
      "name": "session",
      "value": "your-session-token",
      "domain": ".example.com",
      "path": "/",
      "secure": true,
      "httpOnly": true
    }
  ],
  "headers": {
    "Authorization": "Bearer your-token-here",
    "X-Custom-Header": "value"
  }
}
```

## 📊 Report Examples

### JSON Output

```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "target": "https://example.com",
  "timestamp": "2025-12-31T16:07:32Z",
  "findings": [
    {
      "id": "finding-001",
      "severity": "CRITICAL",
      "category": "Hardcoded Cryptographic Key",
      "algorithm": "AES-256-CBC",
      "location": {
        "file": "app.js",
        "line": 42,
        "type": "static"
      },
      "evidence": "const key = '***REDACTED***';",
      "cwe": "CWE-321",
      "owasp": "A02:2021 – Cryptographic Failures",
      "remediation": "Store cryptographic keys in a secure vault or key management system"
    }
  ],
  "summary": {
    "total_findings": 5,
    "critical": 1,
    "high": 2,
    "medium": 2,
    "low": 0
  }
}
```

## 🏗️ Architecture

```
CLI Interface
     ↓
Runtime Controller (Headless Browser)
     ↓
Traffic & Runtime Collector
     ↓
Crypto Detection Engine
     ↓
Correlation & Risk Analyzer
     ↓
Report Generator
```

## 🔒 Security & Ethics

CryptoTrace is designed with security and ethics in mind:

1. **Mandatory Authorization**: Tool refuses to run without explicit authorization flag
2. **Secret Redaction**: All sensitive values are masked by default
3. **No Persistent Storage**: Keys and secrets are not stored on disk
4. **Local Execution**: All processing happens locally, no external data transmission
5. **Audit Logging**: All scans are logged for accountability

## 🧪 Testing

```bash
# Run unit tests
pytest tests/ -v

# Run specific test
pytest tests/test_detector.py -v

# Run with coverage
pytest tests/ --cov=cryptotrace --cov-report=html
```

## 📝 License

MIT License - See LICENSE file for details

## 🤝 Contributing

Contributions are welcome! Please read CONTRIBUTING.md for guidelines.

## ⚖️ Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors and contributors are not responsible for any misuse or damage caused by this tool. Always ensure you have explicit permission before testing any application.

## 📧 Contact

For questions or support, please open an issue on GitHub.
