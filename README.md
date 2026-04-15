# SecureAI HR Risk Scanner

A fully functional Python CLI tool for scanning AI-enabled HR and payroll workflow repositories for practical AI security risks.

## What it checks
- Prompt injection indicators
- Sensitive data exposure such as SSNs
- Hardcoded secrets
- External model routing
- Weak access control logic
- Prompt governance gaps
- Unsafe data minimization patterns

## Why this project matters
This project is designed for AI security work in environments that handle employee data, payroll, compliance workflows, and connected LLM systems.

## Folder layout
- `secureai_hr_risk_scanner.py` - main scanner
- `demo_hr_ai_app/` - runnable target folder to scan tonight
- `reports/` - generated JSON and CSV findings

## Run
```bash
python secureai_hr_risk_scanner.py demo_hr_ai_app
