# LLM Security Scanner

<p align="center">
  <a href="https://github.com/ridhinva/llm-security-scanner/stargazers"><img src="https://img.shields.io/github/stars/ridhinva/llm-security-scanner?style=for-the-badge" alt="Stars"></a>
  <a href="https://github.com/ridhinva/llm-security-scanner/network/members"><img src="https://img.shields.io/github/forks/ridhinva/llm-security-scanner?style=for-the-badge" alt="Forks"></a>
  <a href="https://github.com/ridhinva/llm-security-scanner/issues"><img src="https://img.shields.io/github/issues/ridhinva/llm-security-scanner?style=for-the-badge" alt="Issues"></a>
  <a href="https://github.com/ridhinva/llm-security-scanner/blob/main/LICENSE"><img src="https://img.shields.io/github/license/ridhinva/llm-security-scanner?style=for-the-badge" alt="License"></a>
  <a href="https://github.com/ridhinva/llm-security-scanner/commits/main"><img src="https://img.shields.io/github/last-commit/ridhinva/llm-security-scanner?style=for-the-badge" alt="Last Commit"></a>
  <a href="https://github.com/ridhinva/llm-security-scanner/actions"><img src="https://img.shields.io/github/actions/workflow/status/ridhinva/llm-security-scanner/ci.yml?style=for-the-badge" alt="Build Status"></a>
  <img src="https://img.shields.io/badge/OWASP-LLM%20Top%2010%202024-critical?style=for-the-badge" alt="OWASP LLM">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=for-the-badge" alt="Platform">
</p>

---

## 🎯 Overview

**OWASP LLM Top 10 2024 vulnerability scanner** for AI/LLM applications. Detects prompt injection, RAG poisoning, model poisoning, excessive agency, insecure output handling, and agent hijacking.

| Check | OWASP LLM Category | Severity |
|-------|-------------------|----------|
| Direct Prompt Injection | LLM01 | 🔴 CRITICAL |
| Indirect Prompt Injection (RAG) | LLM01 | 🔴 CRITICAL |
| Insecure Output Handling | LLM02 | 🟠 HIGH |
| Training Data Poisoning | LLM03 | 🟠 HIGH |
| Model DoS | LLM04 | 🟡 MEDIUM |
| Supply Chain Vulnerabilities | LLM05 | 🟠 HIGH |
| Sensitive Info Disclosure | LLM06 | 🟠 HIGH |
| Insecure Plugin Design | LLM07 | 🟠 HIGH |
| Excessive Agency | LLM08 | 🔴 CRITICAL |
| Overreliance | LLM09 | 🟡 MEDIUM |
| Model Theft | LLM10 | 🟡 MEDIUM |

---

## ✨ Features

- 🔍 **Multi-vector scanning** — API endpoints, RAG systems, plugins, agents
- 🎯 **OWASP LLM Top 10 2024 coverage** — All 10 categories
- 🤖 **Agent-aware** — Multi-agent system hijacking detection
- 📝 **Context-aware** — RAG/document poisoning checks
- 🛡️ **Safe by default** — Read-only testing, no exploitation
- 📦 **Extensible** — Custom payload sets, custom checks

---

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/ridhinva/llm-security-scanner.git
cd llm-security-scanner
pip install requests
```

### Usage

#### Scan LLM API endpoint
```bash
python3 llm_security_scanner.py --target https://api.example.com/v1/chat/completions --api-key YOUR_KEY
```

#### Scan RAG system
```bash
python3 llm_security_scanner.py --target https://rag.example.com --mode rag --documents docs/
```

#### Scan AI agent system
```bash
python3 llm_security_scanner.py --target https://agent.example.com --mode agent --framework langchain
```

#### Test prompt injection payloads
```bash
python3 llm_security_scanner.py --target https://api.example.com --payloads payloads/prompt_injection.txt
```

---

## 🔧 How It Works

| Mode | Checks |
|------|--------|
| `api` | Direct/indirect injection, output handling, info disclosure |
| `rag` | Document poisoning, retrieval manipulation, context overflow |
| `plugin` | Parameter validation, auth bypass, excessive permissions |
| `agent` | Goal hijacking, tool misuse, inter-agent communication |

---

## 📚 References

- [OWASP LLM Top 10 2024](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Prompt Injection Research](https://simonwillison.net/2023/Sep/27/prompt-injection/)
- [RAG Poisoning](https://arxiv.org/abs/2402.07831)

---

## ⚖️ Disclaimer

For authorized security testing and educational purposes only. Unauthorized testing of AI systems is prohibited.

---

## 👤 Author

**[@c_y_p_h3r](https://x.com/c_y_p_h3r)** — Bug bounty hunter & security researcher