import pandas as pd
import requests
import os
from dotenv import load_dotenv

# Load API keys
load_dotenv()
OTX_API_KEY = os.getenv("OTX_API_KEY")

# Load local scan results
df = pd.read_csv("gvm_results.csv")  # change if needed

# Load CISA KEV from JSON
kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
response = requests.get(kev_url, timeout=10)
kev_data = response.json()
kev_list = [entry["cveID"] for entry in kev_data["vulnerabilities"]]

# Function to check if any CVE in a cell is in KEV
def check_kev(cve_field):
    if pd.isna(cve_field):
        return "No"
    cves = [c.strip() for c in cve_field.split(",")]
    return "Yes" if any(cve in kev_list for cve in cves) else "No"

# Query OTX for total pulse count for all CVEs in a cell
def query_otx_total(cve_field):
    if pd.isna(cve_field):
        return 0
    total = 0
    headers = {'X-OTX-API-KEY': OTX_API_KEY}
    for cve in [c.strip() for c in cve_field.split(",") if c.startswith("CVE-")]:
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/cve/{cve}/general"
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                total += r.json()['pulse_info']['count']
        except Exception as e:
            print(f"Error querying {cve}: {e}")
    return total

def check_exploit_available(cve_field):
    if pd.isna(cve_field):
        return "No"
    for cve in [c.strip() for c in cve_field.split(",") if c.startswith("CVE-")]:
        try:
            url = f"https://vulners.com/api/v3/search/lucene/?query=cve:{cve}"
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                data = r.json()
                if data.get('data', {}).get('total', 0) > 0:
                    return "Yes"
        except Exception as e:
            print(f"Error checking exploit for {cve}: {e}")
    return "No"


# Apply enrichment
df['In_KEV'] = df['CVEs'].apply(check_kev)
df['OTX_Pulses'] = df['CVEs'].apply(query_otx_total)
df['Exploit_Available'] = df['CVEs'].apply(check_exploit_available)

# Compute Threat-Aware Risk Score
def risk_score(row):
    try:
        base = float(row['Severity']) if not pd.isna(row['Severity']) else 0
    except:
        base = 0
    kev_boost = 10 if row['In_KEV'] == 'Yes' else 0
    otx_boost = min(row['OTX_Pulses'], 5)
    exploit_boost = 3 if row['Exploit_Available'] == 'Yes' else 0
    return base + kev_boost + otx_boost + exploit_boost

df['Threat_Aware_Score'] = df.apply(risk_score, axis=1)

def classify_threat(score):
    if score >= 18:
        return "Critical"
    elif score >= 12:
        return "High"
    elif score >= 6:
        return "Medium"
    elif score > 0:
        return "Low"
    else:
        return "None"

df['Threat_Level'] = df['Threat_Aware_Score'].apply(classify_threat)

# Save final enriched output
df.to_csv("threat_enriched_output.csv", index=False)
print("[+] Enrichment complete. Output: threat_enriched_output.csv")
