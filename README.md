# 🛡️ Nessus PDF Report → Excel Automation

> *"Manual reporting is the enemy of efficiency. Automate the noise. Focus on the hunt."*

A Python tool that parses **Nessus PDF scan reports** and auto-generates clean, structured **Excel (.xlsx)** files — sorted by severity, with CVEs, CVSS scores, affected hosts, and remediation-ready output.

Built during real-world **VAPT assessments** to eliminate hours of manual copy-paste work.

---

## 🚀 What It Does

- Parses one or multiple Nessus PDF reports
- Extracts: Vulnerability Name, Risk Factor, Affected IP:Port, CVSS v3.0, CVE IDs
- Sorts findings: **CRITICAL → HIGH → MEDIUM**
- Auto-generates a clean `.xlsx` report
- Supports merging multiple PDFs into one report
- Handles edge cases with a warnings file

---

## ⚙️ Installation

```bash
git clone https://github.com/akhileshbarad017/nessus-report-automation.git
cd nessus-report-automation
pip install -r requirements.txt
```

### Requirements
```
pdfplumber
pandas
openpyxl
```

---

## 💻 Usage

### Basic
```bash
python nessus_pdf_to_xlsx.py scan1.pdf output.xlsx
```

### Multiple PDFs merged
```bash
python nessus_pdf_to_xlsx.py scan1.pdf scan2.pdf scan3.pdf output.xlsx
```

### Custom minimum risk level
```bash
python nessus_pdf_to_xlsx.py scan.pdf output.xlsx --min-risk high
```

### One row per host
```bash
python nessus_pdf_to_xlsx.py scan.pdf output.xlsx --split-hosts
```

---

## 🔧 Options

| Flag | Default | Description |
|---|---|---|
| `--min-risk` | `medium` | Minimum risk: `critical`, `high`, `medium` |
| `--split-hosts` | Off | One row per affected host |

---

## 🧠 How It Works

```
Nessus PDF(s)
     ↓
Text Extraction (pdfplumber)
     ↓
Regex Parsing (Plugin, Risk, CVSS, CVE, IP, Port)
     ↓
Deduplication + Sorting (CRITICAL → HIGH → MEDIUM)
     ↓
Excel Report (openpyxl + pandas)
```

---

## ⚠️ Legal Disclaimer

> This tool is built for **authorized penetration testing and VAPT assessments only**.
> Use only on systems you have explicit written permission to test.
> Unauthorized use is illegal and unethical.

---

## 👤 Author

**Akhilesh Barad**
Penetration Tester | VAPT Analyst | Bug Bounty Hunter

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://linkedin.com/in/akhilesh-barad-39091a3a1)

---

## ⭐ If this saved your time — give it a star!
