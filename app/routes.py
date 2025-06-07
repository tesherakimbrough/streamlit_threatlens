from flask import Flask, render_template, request, session
import requests
import socket
import plotly.graph_objs as go
import plotly.io as pio
import base64
import os
import pandas as pd

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = os.getenv("THREATLENS_SECRET", "threatlens_secret_key_2025")

def resolve_to_ip(query):
    """Try to resolve a domain to an IP. If already an IP, return as is."""
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
        # Try resolving as domain
        return socket.gethostbyname(query)
    except Exception:
        return None

def get_ip_enrichment(ip):
    """Return (country, org, asn) for the given IP using ip-api.com."""
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=4)
        data = resp.json()
        if data["status"] == "success":
            country = data.get("countryCode", "")
            org = data.get("org", "")
            asn = data.get("as", "")
            return country, org, asn
        else:
            return "", "", ""
    except Exception:
        return "", "", ""

def get_recommended_action(score, country):
    risky_countries = {"RU", "CN", "KP", "IR", "BY"}
    if score is None:
        return ""
    if score >= 70:
        return "Block"
    elif 20 <= score < 70:
        if country in risky_countries:
            return "Block"
        else:
            return "Monitor"
    else:
        return "Safe"

def create_bar_chart(score, reports):
    data = [
        go.Bar(
            x=['Abuse Confidence Score', 'Total Reports'],
            y=[score, reports],
            marker=dict(color=['#19c37d', '#277be7'])
        )
    ]
    layout = go.Layout(
        title='Threat Metrics',
        yaxis=dict(title='Value'),
        plot_bgcolor='#23272f',
        paper_bgcolor='#23272f',
        font=dict(color='#f3f4f6')
    )
    fig = go.Figure(data=data, layout=layout)
    img_bytes = pio.to_image(fig, format='png')
    base64_img = base64.b64encode(img_bytes).decode('ascii')
    return base64_img

def check_abuseipdb(ip):
    API_KEY = "4f2031b6ff071a91c34b0b5cc03cbd77cbfda36f3f535ee0b6f19fa54d882805ee3a85d2da549fec"  # <-- Replace with your real key!
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90"
    }
    try:
        response = requests.get(url, headers=headers, params=params, timeout=6)
        if response.status_code == 200:
            data = response.json()["data"]
            display = f"""IP: {data['ipAddress']}
Abuse Confidence Score: {data['abuseConfidenceScore']}
Country: {data['countryCode']}
Total Reports: {data['totalReports']}
Last Reported At: {data['lastReportedAt']}"""
            score = int(data['abuseConfidenceScore'])
            reports = int(data['totalReports'])
            return display, score, reports, data['countryCode']
        elif response.status_code == 422:
            return "Invalid input. Please enter a valid IP address or domain (e.g., 8.8.8.8 or google.com).", None, None, ""
        else:
            return f"Error: {response.status_code} - {response.text}", None, None, ""
    except Exception as e:
        return f"Error contacting AbuseIPDB: {e}", None, None, ""

@app.route('/', methods=['GET', 'POST'])
def home():
    result = None
    query = ""
    chart = None
    verdict = None
    batch_results = None
    enrich_single = {}

    if 'history' not in session:
        session['history'] = []

    if request.method == 'POST':
        # Batch CSV upload
        if 'batchfile' in request.files and request.files['batchfile'].filename != '':
            file = request.files['batchfile']
            df = pd.read_csv(file)
            results = []
            for idx, row in df.iterrows():
                q = str(row['query']).strip()
                ip = resolve_to_ip(q)
                country = org = asn = ""
                if ip is None:
                    verdict = None
                    abuse_result = "Could not resolve"
                    score = None
                    reports = None
                else:
                    abuse_result, score, reports, abuse_country = check_abuseipdb(ip)
                    country, org, asn = get_ip_enrichment(ip)
                    if score is not None:
                        if score < 20:
                            verdict = "Safe"
                        elif score < 70:
                            verdict = "Risky"
                        else:
                            verdict = "Malicious"
                    else:
                        verdict = None
                recommended_action = get_recommended_action(score, country)
                results.append({
                    'query': q,
                    'ip': ip if ip else "",
                    'result': abuse_result,
                    'score': score,
                    'reports': reports,
                    'verdict': verdict,
                    'country': country,
                    'org': org,
                    'asn': asn,
                    'recommended_action': recommended_action
                })
            batch_results = results
        else:
            # Single lookup
            query = request.form.get('query', '')
            ip = resolve_to_ip(query)
            country = org = asn = ""
            if ip is None:
                result = "Could not resolve the domain. Please enter a valid IP address or domain."
                verdict = None
            else:
                result, score, reports, abuse_country = check_abuseipdb(ip)
                country, org, asn = get_ip_enrichment(ip)
                if score is not None:
                    if score < 20:
                        verdict = "Safe"
                    elif score < 70:
                        verdict = "Risky"
                    else:
                        verdict = "Malicious"
                if score is not None and reports is not None:
                    chart = create_bar_chart(score, reports)
                # Save to history
                history = session['history']
                history.append({'query': query, 'verdict': verdict})
                session['history'] = history[-5:]
            recommended_action = get_recommended_action(score, country)
            enrich_single = {'country': country, 'org': org, 'asn': asn, 'recommended_action': recommended_action}

    return render_template("index.html",
                           result=result,
                           query=query,
                           chart=chart,
                           verdict=verdict,
                           history=session.get('history', []),
                           batch_results=batch_results,
                           enrich_single=enrich_single)

if __name__ == "__main__":
    app.run(debug=True)
