# AI SOC Investigation Assistant

An AI assistant that investigates security alerts like a SOC analyst: it extracts IOCs, enriches them with
threat intelligence, correlates SIEM-style logs, maps behaviour to MITRE ATT&CK and recommends response actions.

## Problem
SOC analysts receive many alerts and spend significant time investigating each one manually.
This project automates the investigation steps and leaves the final decision to a human.

## Pipeline
Alert → IOC extraction → Threat intelligence (AbuseIPDB, VirusTotal) → Log correlation (SQLite)
→ MITRE ATT&CK mapping → LLM verdict (Gemini) → API (FastAPI) → Dashboard (Streamlit)

## Design decisions
- Deterministic code gathers the evidence; the LLM only reasons over it.
- LLM output is validated against a schema, and every ATT&CK ID is checked against the real ATT&CK dataset.
- Recommended actions are suggestions for a human to approve; nothing runs automatically.
- Retries, backoff and fallback models handle LLM overload and quota limits.

## Setup
1. `python -m venv venv` then `venv\Scripts\activate`
2. `pip install -r requirements.txt`
3. Create `.env` (never commit it):
```
   ABUSEIPDB_API_KEY=...
   VIRUSTOTAL_API_KEY=...
   GEMINI_API_KEY=...
   LLM_MODEL=gemini-3.5-flash
   LLM_FALLBACK_MODELS=gemini-3.6-flash,gemini-3-flash-preview
```
4. Download data:
   - ATT&CK: `enterprise-attack.json` from the `mitre-attack/attack-stix-data` GitHub repository into `data/`
   - Feodo lists from abuse.ch into `data/feodo.txt` and `data/feodo_aggressive.txt`
5. Build the data: `python generate_data.py`, `python -m app.load_data`, then `python generate_eval_data.py` (optional)
6. Run: `uvicorn app.main:app --reload` and, in a second terminal, `streamlit run dashboard/app.py`

## Evaluation (12 labelled synthetic alerts: 7 attacks, 5 benign)
| Metric | AI pipeline | A: trust every alert | B: rules + threat intel |
|---|---|---|---|
| Verdict accuracy | 100% | 58% | 50% |
| Attacks caught | 100% | 100% | 14% |
| Benign wrongly escalated | 0% | 100% | 0% |

ATT&CK recall: rules only 9/21, updated rules 14/21, rules + LLM 17/21 (precision 17/23).

## Limitations
Small synthetic dataset written by the author; one run per alert; model confidence is not calibrated;
free-tier LLM data handling means real company logs should not be used.