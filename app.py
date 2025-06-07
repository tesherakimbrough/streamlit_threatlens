import streamlit as st
import pandas as pd
import socket
import plotly.graph_objects as go
from deep_translator import GoogleTranslator
import random

# DEMO_MODE → if True = no API key needed, safe for public demo
DEMO_MODE = True

# Resolve to IP function
def resolve_to_ip(query):
    try:
        socket.inet_aton(query)
        return query
    except socket.error:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, query)
        return query
    except socket.error:
        pass
    try:
        return socket.gethostbyname(query)
    except Exception:
        return None

# Check AbuseIPDB function (DEMO MODE returns fake data)
def check_abuseipdb(ip):
    if DEMO_MODE:
        return {
            "ip": ip,
            "score": random.choice([0, 10, 25, 50, 75, 100]),
            "reports": random.randint(0, 250),
            "country": random.choice(["US", "JP", "DE", "FR", "IN", "BR"]),
            "org": random.choice(["Google LLC", "Amazon AWS", "Microsoft Azure"]),
            "asn": random.choice(["AS15169", "AS16509", "AS8075"]),
            "lastReportedAt": "2025-06-06T12:00:00+00:00"
        }
    else:
        return None  # Real mode not implemented in this example

# Bar chart for visualization
def create_bar_chart(score, reports):
    fig = go.Figure(data=[
        go.Bar(x=["Abuse Confidence Score", "Total Reports"], y=[score, reports])
    ])
    fig.update_layout(title="Threat Metrics", yaxis_title="Value")
    return fig

# --- Streamlit App ---

# Page config
st.set_page_config(page_title="ThreatLens (Streamlit)", page_icon="👁️", layout="centered")

# Title
st.title("👁️ ThreatLens (Streamlit)")
st.subheader("Instant Threat Intelligence Lookups for IPs and Domains")

# Language selection
language_map = {
    "English": "en",
    "Spanish": "es",
    "French": "fr",
    "German": "de",
    "Japanese": "ja",
    "Chinese (Simplified)": "zh-CN"
}

selected_language = st.selectbox("🌐 Select Language", list(language_map.keys()))
target_lang_code = language_map[selected_language]

# DEMO mode notice
st.info("⚠️ Running in DEMO MODE — results are simulated!")

# --- Single IP/Domain Lookup ---
st.header("🔍 Single IP/Domain Lookup")
query = st.text_input("Enter IP Address or Domain:")
if st.button("Check Threat"):
    ip = resolve_to_ip(query)
    if not ip:
        st.error("Could not resolve the domain.")
    else:
        result = check_abuseipdb(ip)
        if result:
            # Original result text
            result_text = f"""
IP: {result['ip']}
Country: {result['country']}
Org: {result['org']}
ASN: {result['asn']}
Abuse Confidence Score: {result['score']}
Total Reports: {result['reports']}
Last Reported At: {result['lastReportedAt']}
"""
            # Translate result
            translated_text = GoogleTranslator(source='auto', target=target_lang_code).translate(result_text)
            st.text(translated_text)
            st.plotly_chart(create_bar_chart(result['score'], result['reports']))

# --- Batch Lookup ---
st.header("📂 Batch Lookup (CSV)")
st.caption("Upload CSV with column 'query'")
uploaded_file = st.file_uploader("Drag and drop file here", type=["csv"])
if uploaded_file:
    df = pd.read_csv(uploaded_file)
    if 'query' not in df.columns:
        st.error("CSV must contain a column named 'query'.")
    else:
        batch_results = []
        for q in df['query']:
            ip = resolve_to_ip(q)
            if ip:
                result = check_abuseipdb(ip)
                if result:
                    batch_results.append({
                        "IP": result['ip'],
                        "Country": result['country'],
                        "Org": result['org'],
                        "ASN": result['asn'],
                        "Score": result['score'],
                        "Reports": result['reports'],
                        "Last Reported": result['lastReportedAt']
                    })
        if batch_results:
            batch_df = pd.DataFrame(batch_results)
            st.dataframe(batch_df)

# --- Footer ---
st.markdown("---")
st.markdown("Built by Teshera Kimbrough 2025 | GitHub: [ThreatLens](https://github.com/tesherakimbrough/streamlit_threatlens)")
