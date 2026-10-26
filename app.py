import ipaddress
import os

import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

st.set_page_config(
    page_title="OSINT Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
)
st.title("🛡️ OSINT Threat Intelligence Dashboard")
st.markdown("Query threat-intelligence services for a domain or IP address.")

VT_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
OTX_KEY = os.getenv("ALIENVAULT_API_KEY", "").strip()

with st.sidebar:
    st.header("🔌 API Connection Status")
    st.success("VirusTotal key loaded") if VT_KEY else st.warning("VirusTotal key missing")
    st.success("AbuseIPDB key loaded") if ABUSE_KEY else st.warning("AbuseIPDB key missing")
    st.success("AlienVault OTX key loaded") if OTX_KEY else st.warning("AlienVault OTX key missing")
    st.info("crt.sh does not require an API key.")

target = st.text_input(
    "Enter a domain or IP address:",
    placeholder="e.g., 8.8.8.8 or github.com",
).strip()


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def get_json(url, *, headers=None, params=None, timeout=15):
    """Make a GET request and return parsed JSON, or raise a useful error."""
    response = requests.get(
        url,
        headers=headers,
        params=params,
        timeout=timeout,
    )
    if not response.ok:
        raise RuntimeError(f"HTTP {response.status_code}: {response.text[:500]}")
    return response.json()


def fetch_complete_osint(target_query: str):
    results = {}
    is_ip = is_ip_address(target_query)

    if VT_KEY:
        try:
            indicator_type = "ip_addresses" if is_ip else "domains"
            url = f"https://www.virustotal.com/api/v3/{indicator_type}/{target_query}"
            results["virustotal"] = get_json(
                url,
                headers={"x-apikey": VT_KEY},
            )
        except Exception as exc:
            results["virustotal_error"] = str(exc)

    if ABUSE_KEY and is_ip:
        try:
            results["abuseipdb"] = get_json(
                "https://api.abuseipdb.com/api/v2/check",
                headers={
                    "Key": ABUSE_KEY,
                    "Accept": "application/json",
                },
                params={
                    "ipAddress": target_query,
                    "maxAgeInDays": 90,
                },
            )
        except Exception as exc:
            results["abuseipdb_error"] = str(exc)

    if OTX_KEY:
        try:
            indicator_type = "IPv4" if is_ip else "domain"
            url = (
                "https://otx.alienvault.com/api/v1/indicators/"
                f"{indicator_type}/{target_query}/general"
            )
            results["alienvault"] = get_json(
                url,
                headers={"X-OTX-API-KEY": OTX_KEY},
            )
        except Exception as exc:
            results["alienvault_error"] = str(exc)

    # crt.sh is for domain certificate records; skip it for IP addresses.
    if not is_ip:
        try:
            results["certificates"] = get_json(
                "https://crt.sh/",
                params={"q": target_query, "output": "json"},
            )[:5]
        except Exception as exc:
            results["certificates_error"] = str(exc)

    return results


if st.button("Execute Scan"):
    if not target:
        st.error("Enter a domain or IP address.")
    else:
        with st.spinner(f"Gathering results for {target}..."):
            data = fetch_complete_osint(target)

        col1, col2 = st.columns(2)

        with col1:
            st.subheader("🔴 VirusTotal")
            if "virustotal_error" in data:
                st.error(data["virustotal_error"])
            elif "virustotal" in data:
                attributes = data["virustotal"].get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                if stats:
                    malicious = stats.get("malicious", 0)
                    st.metric(
                        "Malicious detections",
                        malicious,
                        delta="Threat detections" if malicious else "No malicious detections",
                        delta_color="inverse" if malicious else "normal",
                    )
                    st.json(stats)
                else:
                    st.info("No analysis statistics were returned.")
            else:
                st.info("VirusTotal key is not configured.")

        with col2:
            st.subheader("⚠️ AbuseIPDB")
            if "abuseipdb_error" in data:
                st.error(data["abuseipdb_error"])
            elif "abuseipdb" in data:
                abuse_data = data["abuseipdb"].get("data", {})
                st.metric(
                    "Abuse confidence score",
                    f"{abuse_data.get('abuseConfidenceScore', 0)}%",
                )
                st.write(f"**Total reports:** {abuse_data.get('totalReports', 0)}")
                st.write(f"**Country:** {abuse_data.get('countryCode', 'Unknown')}")
                st.write(f"**ISP:** {abuse_data.get('isp', 'N/A')}")
            elif is_ip_address(target):
                st.info("AbuseIPDB key is missing or no result was returned.")
            else:
                st.info("AbuseIPDB checks IP addresses only.")

        st.divider()
        col3, col4 = st.columns(2)

        with col3:
            st.subheader("🌌 AlienVault OTX")
            if "alienvault_error" in data:
                st.error(data["alienvault_error"])
            elif "alienvault" in data:
                pulse_info = data["alienvault"].get("pulse_info", {})
                st.metric("Linked threat pulses", pulse_info.get("count", 0))

                pulses = pulse_info.get("pulses", [])[:3]
                if pulses:
                    for pulse in pulses:
                        st.write(
                            f"• **{pulse.get('name', 'Unnamed pulse')}** "
                            f"(Author: {pulse.get('author_name', 'Unknown')})"
                        )
                else:
                    st.write("No linked pulses were returned.")
            else:
                st.info("AlienVault OTX key is not configured.")

        with col4:
            st.subheader("📜 Certificate records (crt.sh)")
            if "certificates_error" in data:
                st.error(data["certificates_error"])
            elif "certificates" in data:
                certificates = data["certificates"]
                if certificates:
                    for cert in certificates:
                        st.markdown(f"**Common name:** `{cert.get('common_name', 'N/A')}`")
                        st.write(f"Issuer: {cert.get('issuer_name', 'N/A')}")
                        st.write("---")
                else:
                    st.info("No certificate records were returned.")
            else:
                st.info("Certificate lookup is skipped for IP addresses.")
