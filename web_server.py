#!/usr/bin/env python3
from flask import Flask, render_template_string
import os
import json

app = Flask(__name__)
JSON_LOG = os.path.expanduser("~/dns-spoofing-detector/logs/latest_attack.json")

HTML_PAGE = '''
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>⚠️ DNS Spoofing Detected</title>
  <style>
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background: linear-gradient(135deg, #f44336, #c62828);
      color: white;
      text-align: center;
      padding: 40px;
    }
    .container {
      max-width: 700px;
      margin: 0 auto;
      background: rgba(0,0,0,0.3);
      padding: 30px;
      border-radius: 15px;
      box-shadow: 0 8px 20px rgba(0,0,0,0.5);
    }
    h1 { color: #ffeb3b; margin-top: 0; }
    .info {
      background: #b71c1c;
      padding: 18px;
      margin: 25px 0;
      border-radius: 10px;
      text-align: left;
      font-family: Consolas, monospace;
      font-size: 1.1em;
      line-height: 1.8;
    }
    .footer {
      margin-top: 30px;
      font-size: 0.9em;
      opacity: 0.9;
    }
    .icon { font-size: 70px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="icon">⚠️</div>
    <h1>DNS SPOOFING ATTACK DETECTED</h1>
    <p><strong>Your access has been blocked for security.</strong></p>

    {% if attack %}
      <div class="info">
        <strong>🎯 Domain:</strong> {{ attack.domain }}<br>
        <strong>🔥 Spoofed IP:</strong> <span style="color:#f44">{{ attack.spoofed_ip }}</span><br>
        <strong>✅ Expected IP(s):</strong> 
        {% if attack.expected_ips %}
          {{ attack.expected_ips | join(', ') }}
        {% else %}
          Unknown
        {% endif %}<br>
        <strong>⏱️ TTL:</strong> {{ attack.ttl }} sec<br>
        <strong>🔢 TXID:</strong> {{ attack.txid }}<br>
        <strong>⏰ Detected at:</strong> {{ attack.timestamp }}
      </div>
      <p><em>You are protected from a potential phishing or MITM attack.</em></p>
    {% else %}
      <p>No recent attack detected. This network is currently safe.</p>
    {% endif %}

    <div class="footer">
      🔐 Protected by: DNS Spoofing Detection System<br>
      Built with Python, Scapy, and Flask
    </div>
  </div>
</body>
</html>
'''

@app.route("/")
def home():
    try:
        with open(JSON_LOG, "r") as f:
            attack = json.load(f)
    except Exception as e:
        attack = None
    return render_template_string(HTML_PAGE, attack=attack)

if __name__ == "__main__":
    print("🚀 Web Server Running on http://0.0.0.0:80")
    app.run(host="0.0.0.0", port=80)