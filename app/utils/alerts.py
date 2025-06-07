import os
import requests
from dotenv import load_dotenv

# Load environment variables from .env file if present
load_dotenv()

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL")
GOOGLE_CHAT_WEBHOOK_URL = os.getenv("GOOGLE_CHAT_WEBHOOK_URL")

def send_alert(ip, verdict, details):
    """
    Send an alert to all configured chat platforms (Slack, Teams, Google Chat).
    Any webhook URL can be left unset if not used.
    """
    message_text = (
        f"🚨 ThreatLens Alert 🚨\n"
        f"*IP/Domain:* `{ip}`\n"
        f"*Verdict:* *{verdict}*\n"
        f"*Details:*\n{details}"
    )

    # Slack payload (Markdown supported)
    slack_payload = {"text": message_text}
    # Teams payload (Markdown supported)
    teams_payload = {"text": message_text}
    # Google Chat payload (Plain text)
    gchat_payload = {"text": message_text}

    # Send to Slack if configured
    if SLACK_WEBHOOK_URL:
        try:
            resp = requests.post(SLACK_WEBHOOK_URL, json=slack_payload, timeout=5)
            if resp.status_code != 200:
                print(f"Slack alert failed: {resp.text}")
        except Exception as e:
            print(f"Error sending Slack alert: {e}")

    # Send to Teams if configured
    if TEAMS_WEBHOOK_URL:
        try:
            resp = requests.post(TEAMS_WEBHOOK_URL, json=teams_payload, timeout=5)
            if resp.status_code != 200:
                print(f"Teams alert failed: {resp.text}")
        except Exception as e:
            print(f"Error sending Teams alert: {e}")

    # Send to Google Chat if configured
    if GOOGLE_CHAT_WEBHOOK_URL:
        try:
            resp = requests.post(GOOGLE_CHAT_WEBHOOK_URL, json=gchat_payload, timeout=5)
            if resp.status_code != 200:
                print(f"Google Chat alert failed: {resp.text}")
        except Exception as e:
            print(f"Error sending Google Chat alert: {e}")
