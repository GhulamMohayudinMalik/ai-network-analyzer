# 🛡️ AI Network Analyzer

> **Intelligent Network Security Scanner with AI-Powered Threat Intelligence**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive Python-based network security analysis tool that scans networks, identifies vulnerabilities, matches CVEs, and provides AI-driven threat intelligence with severity predictions.

## ✨ Features

- 🔍 **Network Scanning** - Discover hosts on any network
- 🚪 **Port Scanning** - Identify open ports with multiple scan types
- 🔧 **Service Detection** - Fingerprint services and versions
- 🔒 **CVE Matching** - Match services to known vulnerabilities
- 📊 **CVSS Scoring** - Display severity scores for CVEs
- 🎯 **Severity Prediction** - AI-based threat level classification
- 🤖 **AI Threat Intelligence** - Intelligent analysis & recommendations
- 📑 **Color-Coded Reports** - Beautiful CLI, HTML & PDF reports

## 📋 Requirements

- Python 3.10 or higher
- [Nmap](https://nmap.org/download.html) installed and in PATH

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/AI-Network-Analyzer.git
cd AI-Network-Analyzer

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```bash
# Check system requirements
python -m src.main check

# Scan a target (coming in Phase 1.2)
python -m src.main scan --target 192.168.1.1

# Generate a report (coming in Phase 3)
python -m src.main report --input results.json --format html

# Generate default config file
python -m src.main init-config
```

## 📁 Project Structure

```
AI-Network-Analyzer/
├── src/
│   ├── core/           # Configuration, logging, exceptions
│   ├── scanner/        # Network/port scanning (Phase 1.2-1.4)
│   ├── vulnerability/  # CVE matching (Phase 2)
│   ├── intelligence/   # AI analysis (Phase 4)
│   ├── reporting/      # Reports (Phase 3)
│   └── main.py         # CLI entry point
├── data/               # CVE cache and scan results
├── logs/               # Log files
├── reports/            # Generated reports
├── config.yaml         # Default configuration
├── requirements.txt    # Python dependencies
└── project.md          # Detailed project documentation
```

## ⚙️ Configuration

Copy `.env.example` to `.env` and configure:

```bash
# API Keys (optional but recommended)
NVD_API_KEY=your_nvd_api_key
OPENAI_API_KEY=your_openai_key

# Settings
DEBUG=false
LOG_LEVEL=INFO
```

Or use the YAML configuration file:

```bash
python -m src.main init-config -o my_config.yaml
python -m src.main --config my_config.yaml scan --target 192.168.1.1
```

## 📖 Documentation

See [project.md](project.md) for detailed project documentation including:
- Complete feature list
- Development phases and milestones
- Technology stack
- Improvement suggestions

## ⚠️ Legal Notice

**Only scan networks you own or have explicit permission to scan.** Unauthorized scanning may be illegal in your jurisdiction.

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details.

---

*Built with ❤️ for the security community*
