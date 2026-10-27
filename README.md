# 🛡️ OSINT Threat Intelligence Dashboard

A Streamlit web app that takes a domain or IP address and pulls reputation and context data about it from four public threat-intelligence sources, then shows the results side by side in one dashboard.

It is a **passive** tool: it asks third-party services what they already know about a target. It does not send any traffic to the target itself.

## Screenshots

![Dashboard overview](https://github.com/user-attachments/assets/738de04c-c5d3-478f-8ba5-b952602ceb2e)

![Scan results](https://github.com/user-attachments/assets/4e95bbca-0114-48e8-a88a-80c0e9b2a23b)

## What it does

Enter a domain (`github.com`) or an IP address (`8.8.8.8`) and click **Execute Scan**. The app detects which one you entered and queries the sources that apply:

| Source | Works on | What the dashboard shows |
|---|---|---|
| **VirusTotal** | Domains and IPs | Number of engines flagging the target as malicious, plus the full detection breakdown |
| **AbuseIPDB** | IPs only | Abuse confidence score (last 90 days), total reports, country, ISP |
| **AlienVault OTX** | Domains and IPs | Number of linked threat pulses and the first three pulse names with their authors |
| **crt.sh** | Domains only | The first five certificate records (common name and issuer) |

If an API key is missing, that source is skipped and the sidebar shows which keys were loaded. A failed request shows an error message in that panel instead of crashing the app. crt.sh needs no key.

## Setup

**Requirements:** Python 3.9+

```bash
git clone https://github.com/oliverthomasalvesmorrill-lgtm/osint-dashboard.git
cd osint-dashboard
pip install -r requirements.txt
```

Create a `.env` file (see `.env.example`) with your own free API keys:

```
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
ALIENVAULT_API_KEY=your_key_here
```

Run the app:

```bash
streamlit run app.py
```

Then open the local address Streamlit prints (usually http://localhost:8501).

## Ethical use

This tool only queries public threat-intelligence databases, but the targets you enter are still sent to those services. Use it for research, learning, and defensive work. Do not enter private or sensitive information, and do not use results to harass or target anyone.

## Known limitations

- Free API tiers have rate limits (VirusTotal's is strict), so repeated scans can start returning errors.
- crt.sh can be slow or time out, and only the first five certificates are shown.
- The OTX lookup currently treats every IP as IPv4, so IPv6 addresses may not return results there.
- Input is not yet validated beyond checking whether it is an IP, so URLs like `https://example.com` need to be entered as plain domains.

## Roadmap

- [ ] Validate and clean input (strip `https://`, reject private and reserved IP ranges)
- [ ] Fix IPv6 handling for AlienVault OTX
- [ ] Cache results so repeat lookups don't burn API quota
- [ ] Export results to JSON or CSV

## What I learned

The hardest part wasn't the code, it was the environment. My API keys kept acting up and Streamlit kept crashing. Creating a second virtual environment (`.venv`) and reinstalling everything fixed it, which taught me why isolating a project's dependencies matters. The API calls themselves were straightforward.

## Built with

Python, [Streamlit](https://streamlit.io), [Requests](https://requests.readthedocs.io), python-dotenv
