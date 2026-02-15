## Indicator Inspector - Local Model

This repository contains the **Local Model** for the Indicator Inspector project. It is designed for air-gapped, offline environments that require strict compliance with standards such as **CMMC**, **ITAR**, and **FIPS**. This model operates independently of any live threat feeds or cloud-based LLMs.

---

### 📁 Project Structure

```bash
indicator_inspector_local/
├── core/                    # Core enrichment, scoring, and parsing logic
│   ├── enrich_local.py
│   ├── heuristics.py
│   ├── scoring.py
│   └── utils.py
├── cli/                     # CLI entrypoint and CLI tools
│   └── main.py
├── data/                    # Offline threat data (JSON/CSV)
│   └── threatdb.json
├── logs/                    # Enrichment logs and audit files
│   └── activity.log
├── config/                  # Configuration files
│   └── config.yaml
├── LICENSE                  # MIT License
├── SECURITY.md              # Disclosure and compliance statement
├── README.md                # This file
└── setup.py                 # Packaging for distribution
```

---

### 🎯 Key Features

- Fully offline IOC enrichment and scoring
- Designed for secure, compliance-focused environments (CMMC/ITAR)
- Pure Python (no external packages required)
- Easily auditable logic and data flow

---

### ⚠️ Compliance Note

This model does **not** connect to the internet and does not contain any automatic API integrations. Users must manually provide threat intelligence datasets (e.g., AbuseIPDB exports, ThreatFox dumps) in the `data/` directory.

This aligns with:
- CMMC Level 2 control: `SC.L2-3.13.15` (network isolation)
- ITAR control: `22 CFR 120-130` (technical data protection)
- FIPS 199/200 recommendations for information system categorization

For internal validation, all code and data files can be reviewed and hashed to generate a Software Bill of Materials (SBOM).

---

### 🔐 Agentic Model

The **Agentic Model** is a **restricted component** of Indicator Inspector and is not included in this repository. It includes:
- API integrations with VirusTotal, AbuseIPDB, ThreatFox, and OTX
- LLM-driven triage and enrichment agents
- Automated playbook inference and remediation logic

This separation allows the Local Model to remain open-source and secure, while the Agentic Model is reserved for environments that support external connectivity and advanced automation.

---

### ✅ Requirements
- Python 3.8+
- No internet access required
- Runs on Windows, Linux, or macOS

---

### 📜 License
This repository is licensed under the [MIT License](LICENSE).

---

### 🤝 Contributions
At this time, contributions are not being accepted.

The Local Model is provided openly for review, evaluation, and deployment in secure environments, but all development is currently maintained in a closed governance model to ensure alignment with emerging cybersecurity standards.

Please check back in the future for contribution opportunities.

---
