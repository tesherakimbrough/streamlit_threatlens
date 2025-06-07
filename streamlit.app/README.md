# ThreatLens (Streamlit Version)  
Built by Teshera Kimbrough

---

**ThreatLens** is a real-time Threat Intelligence Dashboard built with Streamlit for rapid visualization and accessibility.

This version of ThreatLens runs fully in Streamlit and supports **DEMO MODE** for public use without requiring an API key.

---

## Features

- Instant single IP/domain lookups
- Batch CSV upload and scanning
- Abuse score, reports, country, org, ASN, and verdict
- Dynamic bar charts with Plotly
- Copy/export batch results
- Streamlit UI: easily deploy to Streamlit Cloud for 1-click demo
- Safe **DEMO MODE** — no API key required for demo

---

## Quick Start

```bash
git clone https://github.com/your_username/streamlit_threatlens.git
cd streamlit_threatlens
python -m venv .venv
source .venv/bin/activate   # Or: .venv\Scripts\activate (Windows)
pip install -r requirements.txt
streamlit run app.py

```
--- 

Go to http://localhost:8501 in your browser and explore!

---

## Batch Mode

- Prepare a CSV with column query.
- Upload via the app.
- Download results as CSV.

---

## Deployment (Streamlit Cloud)

1. Push this repo to GitHub (public or private).
2. Go to https://streamlit.io/cloud.
3. Click "New app" → Select your GitHub repo.
4. If using real mode:
- Set ABUSEIPDB_API_KEY in Streamlit Cloud Secrets.
5. Click Deploy → Done! Shareable URL (free).

---

## About

ThreatLens is built by Teshera Kimbrough to showcase applied skills in:

- Python
- Streamlit
- APIs
- Security workflows
- Data visualization
- GitHub Repo (Full Version): ThreatLens

---

## License

MIT License

--- 

