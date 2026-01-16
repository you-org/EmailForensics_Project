#!/usr/bin/env python3

import email
import re
import os
import subprocess
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas



EMAIL_FILE = "phishing_email.eml"
ATTACHMENTS_DIR = "attachments"
REPORT_DIR = "reports"
REPORT_FILE = os.path.join(REPORT_DIR, "forensic_report.pdf")



KEYWORDS = {
    "fr": [
        "sécurité", "connexion", "activité", "compte",
        "urgent", "vérifier", "confirmer"
    ],
    "en": [
        "security", "login", "account", "activity",
        "urgent", "verify", "confirm",
        "password", "update", "suspicious"
    ]
}



def extract_ips(headers: str):
    return re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", headers)


def extract_urls(html: str):
    return re.findall(r'href=["\'](.*?)["\']', html, re.IGNORECASE)


def detect_keywords(body: str):
    detected = []
    body_lower = body.lower()

    for words in KEYWORDS.values():
        for word in words:
            if word in body_lower:
                detected.append(word)

    return list(set(detected))


def analyze_email():
    print("[+] Loading email file...")
    with open(EMAIL_FILE, "r", encoding="utf-8", errors="ignore") as f:
        msg = email.message_from_file(f)

    # ---- Headers analysis
    print("[+] Analyzing headers...")
    received_headers = msg.get_all("Received", [])
    received_text = " ".join(received_headers)

    ips = extract_ips(received_text)
    sender = msg.get("From", "N/A")
    subject = msg.get("Subject", "N/A")

    # ---- Body analysis
    print("[+] Analyzing email body...")
    body = ""

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ["text/html", "text/plain"]:
                payload = part.get_payload(decode=True)
                if payload:
                    body += payload.decode(errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode(errors="ignore")

    urls = extract_urls(body)
    detected_keywords = detect_keywords(body)

    # ---- Attachment extraction
    print("[+] Extracting attachments...")
    os.makedirs(ATTACHMENTS_DIR, exist_ok=True)
    attachments = []

    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            filepath = os.path.join(ATTACHMENTS_DIR, filename)
            with open(filepath, "wb") as f:
                f.write(part.get_payload(decode=True))
            attachments.append(filepath)

    # ---- Metadata analysis
    metadata_results = []
    for file in attachments:
        print(f"[+] Running exiftool on {file}...")
        result = subprocess.run(
            ["exiftool", file],
            capture_output=True,
            text=True
        )
        metadata_results.append(result.stdout)

    return {
        "ips": ips,
        "sender": sender,
        "subject": subject,
        "urls": urls,
        "keywords": detected_keywords,
        "attachments": attachments,
        "metadata": metadata_results
    }



def generate_report(data):
    print("[+] Generating PDF report...")
    os.makedirs(REPORT_DIR, exist_ok=True)

    c = canvas.Canvas(REPORT_FILE, pagesize=A4)
    width, height = A4
    y = height - 50

    # ---- Title
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "Forensic Analysis Report – Phishing Email")
    y -= 40

    c.setFont("Helvetica", 10)
    c.drawString(
        50,
        y,
        f"Analysis date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )
    y -= 30

    # ---- Executive Summary
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "1. Executive Summary")
    y -= 20

    c.setFont("Helvetica", 10)
    c.drawString(
        50,
        y,
        "A suspicious email was analyzed to identify indicators of compromise (IOCs)."
    )
    y -= 40

    # ---- IOCs
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "2. Detected Indicators of Compromise (IOCs)")
    y -= 25

    c.setFont("Helvetica", 10)
    c.drawString(50, y, f"Sender: {data['sender']}")
    y -= 15
    c.drawString(50, y, f"Subject: {data['subject']}")
    y -= 20

    for ip in data["ips"]:
        c.drawString(50, y, f"Source IP detected: {ip}")
        y -= 15

    for url in data["urls"]:
        c.drawString(50, y, f"Phishing URL detected: {url}")
        y -= 15

    if data["keywords"]:
        c.drawString(
            50,
            y,
            f"Suspicious keywords detected: {', '.join(data['keywords'])}"
        )
        y -= 20

    # ---- Recommendations
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "3. Security Recommendations")
    y -= 20

    c.setFont("Helvetica", 10)
    c.drawString(50, y, "- Train users to recognize phishing emails.")
    y -= 15
    c.drawString(50, y, "- Block malicious IP addresses and URLs.")
    y -= 15
    c.drawString(50, y, "- Analyze attachments in a sandboxed environment.")
    y -= 40

    # ---- Ethics
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "4. Ethical and Legal Notice")
    y -= 20

    c.setFont("Helvetica", 10)
    c.drawString(
        50,
        y,
        "This email was generated locally for educational purposes. No real data was used."
    )

    c.save()
    print(f"[+] Report saved to {REPORT_FILE}")



if __name__ == "__main__":
    print("[*] Email Forensics Tool Started")
    results = analyze_email()
    generate_report(results)
    print("[*] Analysis completed successfully")
