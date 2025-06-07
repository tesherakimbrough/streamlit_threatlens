# streamlit_app/app.py

import streamlit as st
import pandas as pd
import requests
import socket
import plotly.graph_objects as go
import random

# ----- CONFIG -----
DEMO_MODE = True  # Set to False if using your real API key
ABUSEIPDB_API_KEY = st.secrets["ABUSEIPDB_API_KEY"] if "ABUSEIPDB_API_KEY" in st.secrets else "YOUR_API_KEY"

# ----- FUNCTIONS -----
def resolve_to_ip(query):
    try:
        socket.inet_aton(query)
        return query  # Valid IPv4
    except socket.error:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, query)
        return query  # Valid IPv6
    except socket.error:
        pass
    try:
        return socket.gethostbyname(query)
    except Exception:
        return None

def check_abuseipdb(ip):
    if DEMO_MODE:
        # Return mock result for public demo
        return {
            "ip": ip,
            "score": random.choice([0, 10, 25, 50, 75, 100]),
            "reports": random.randint(0, 250),
            "country": random.choice(["US", "JP", "DE", "FR", "IN", "BR"]),
            "org": random.choice(["Google LLC", "Amazon AWS", "Microsoft Azure", "Cloudflare", "DigitalOcean"]),
            "asn": random.choice(["AS15169", "AS16509", "AS8075", "AS13335", "AS14061"]),
            "lastReportedAt": "2025-06-06T12:00:00+00:00"
        }
    else:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": "90"
        }
        try:
            response = requests.get(url, headers=headers, params=params, timeout=5)
            if response.status_code == 200:
                data = response.json()["data"]
                return {
                    "ip": data["ipAddress"],
                    "score": data["abuseConfidenceScore"],
                    "reports": data["totalReports"],
                    "country": data["countryCode"],
                    "org": data["isp"],
                    "asn": data["asNumber"],
                    "lastReportedAt": data["lastReportedAt"]
                }
            else:
                return None
        except Exception:
            return None

def create_bar_chart(score, reports):
    fig = go.Figure(data=[
        go.Bar(x=["Abuse Confidence Score", "Total Reports"], y=[score, reports],
               marker_color=['#FF4136', '#0074D9'])
    ])
    fig.update_layout(title="Threat Metrics", yaxis_title="Value")
    return fig

# ----- STREAMLIT UI -----

st.set_page_config(page_title="ThreatLens (Streamlit)", page_icon="👁️", layout="centered")

st.title("👁️ ThreatLens (Streamlit)")
st.subheader("Instant Threat Intelligence Lookups for IPs and Domains")

if DEMO_MODE:
    st.warning("Running in DEMO MODE — results are simulated!")

# SINGLE LOOKUP
st.header("🔍 Single IP/Domain Lookup")
query = st.text_input("Enter IP Address or Domain:")

if st.button("Check Threat"):
    ip = resolve_to_ip(query)
    if not ip:
        st.error("Could not resolve the domain. Please enter a valid IP or domain.")
    else:
        result = check_abuseipdb(ip)
        if result:
            st.success(f"Result for {result['ip']}")
            st.write(f"**Country:** {result['country']} | **Org:** {result['org']} | **ASN:** {result['asn']}")
            st.write(f"**Abuse Confidence Score:** {result['score']} | **Reports:** {result['reports']}")
            st.write(f"**Last Reported At:** {result['lastReportedAt']}")
            st.plotly_chart(create_bar_chart(result['score'], result['reports']))
        else:
            st.error("Failed to retrieve threat data. Check API key or network.")

# BATCH LOOKUP
st.header("📂 Batch Lookup (CSV)")
uploaded_file = st.file_uploader("Upload CSV with column 'query'", type="csv")

if uploaded_file:
    df = pd.read_csv(uploaded_file)
    if "query" not in df.columns:
        st.error("CSV must contain a column named 'query'")
    else:
        st.write("Processing batch...")
        results = []
        for q in df["query"]:
            ip = resolve_to_ip(q)
            if ip:
                data = check_abuseipdb(ip)
                if data:
                    results.append(data)
        if results:
            batch_df = pd.DataFrame(results)
            st.success(f"Processed {len(results)} queries.")
            st.dataframe(batch_df)

            # CSV download button
            csv = batch_df.to_csv(index=False).encode("utf-8")
            st.download_button("📥 Download Results as CSV", data=csv, file_name="batch_results.csv", mime="text/csv")

st.markdown("---")
st.write("**Built by Teshera Kimbrough | GitHub: [ThreatLens](https://github.com/tesherakimbrough/ThreatLens)**")
