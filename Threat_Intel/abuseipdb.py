import requests
import json

def abuseipdb_lookup(ip , api_keys):
    if not api_keys:
        return{
            "status ": "No API-Key Configured"
        }
    if not ip :
        return{
            "status" : "No IP Available "
        }
    
    
    #endpoint to send the request
    endpoint = "https://api.abuseipdb.com/api/v2/check"

    #Headers 
    headers = {
        "Key" : api_keys , 
        "Accept" : "application/json"
    }
    
    #Parameters that abuseipdb expects 
    params = {
    "ipAddress": ip,
    "maxAgeInDays": 90,
    "verbose": ""
    }

    #Response we expect from AbuseIPDB 
    response = requests.get(
    endpoint,
    headers=headers,
    params=params
    )


    if response.status_code != 200:
        return {
            "status": "Error",
            "code": response.status_code
        }
    
    #Saving RAW REPORT
    result = response.json()
    with open("reports/raw_rprt/abuseipdb/abuseipdb_raw_rprt.json", "w", encoding="utf-8") as file:
        json.dump(result, file, indent=4)

    

    #parsing the data and generating a clean report 
    abuse_data = parse_abuseipdb_data(result)
    report = generate_ipdb_report(abuse_data)
    with open("reports/clean_rprt/abuseipdb/abuseipdb_clean_report.txt", "w", encoding="utf-8") as file:
        file.write(report) 
    return abuse_data

def parse_abuseipdb_data(result):

    data = result.get("data", {})

    abuse_confidence = data.get("abuseConfidenceScore", 0)

    if abuse_confidence >= 75:
        verdict = "Malicious"
    elif abuse_confidence >= 25:
        verdict = "Suspicious"
    else:
        verdict = "Clean"

    abuseipdb_data = {

        "ip_address": data.get("ipAddress"),

        "verdict": verdict,
        "abuse_confidence": abuse_confidence,

        "country": data.get("countryName"),
        "country_code": data.get("countryCode"),

        "isp": data.get("isp"),
        "domain": data.get("domain"),

        "usage_type": data.get("usageType"),

        "hostnames": data.get("hostnames", []),

        "is_public": data.get("isPublic"),
        "is_whitelisted": data.get("isWhitelisted"),
        "is_tor": data.get("isTor"),

        "ip_version": data.get("ipVersion"),

        "total_reports": data.get("totalReports"),
        "distinct_users": data.get("numDistinctUsers"),
        "last_reported": data.get("lastReportedAt"),

        "reports": data.get("reports", [])
    }

    return abuseipdb_data

def generate_ipdb_report(abuseipdb_data):

    report = f"""
============================================================
                 ABUSEIPDB THREAT ANALYSIS REPORT
============================================================

IP Summary
----------
IP Address          : {abuseipdb_data.get("ip_address")}
Verdict             : {abuseipdb_data.get("verdict")}
Abuse Confidence    : {abuseipdb_data.get("abuse_confidence")}%
ipdb
Network Information
-------------------
Country             : {abuseipdb_data.get("country")}
Country Code        : {abuseipdb_data.get("country_code")}
ISP                 : {abuseipdb_data.get("isp")}
Domain              : {abuseipdb_data.get("domain")}
Usage Type          : {abuseipdb_data.get("usage_type")}
IP Version          : IPv{abuseipdb_data.get("ip_version")}

Security Attributes
-------------------
Public IP           : {abuseipdb_data.get("is_public")}
Whitelisted         : {abuseipdb_data.get("is_whitelisted")}
TOR Exit Node       : {abuseipdb_data.get("is_tor")}

Abuse Intelligence
------------------
Total Reports       : {abuseipdb_data.get("total_reports")}
Distinct Reporters  : {abuseipdb_data.get("distinct_users")}
Last Reported       : {abuseipdb_data.get("last_reported")}

Hostnames
---------
"""   

    hostnames = abuseipdb_data.get("hostnames", [])

    if hostnames:
        for index, hostname in enumerate(hostnames, start=1):
            report += f"{index}. {hostname}\n"
    else:
        report += "No hostnames associated with this IP.\n"

    report += """

Detailed Abuse Reports
----------------------
"""

    reports = abuseipdb_data.get("reports", [])

    if reports:
        for index, abuse in enumerate(reports, start=1):
            report += f"""
Report {index}
-----------
Reported At : {abuse.get("reportedAt")}
Categories  : {abuse.get("categories")}
Comment     : {abuse.get("comment")}
Reporter    : {abuse.get("reporterCountryName")}
"""
    else:
        report += "No abuse reports available.\n"

    report += f"""

Analyst Interpretation
------------------------------------------------------------

The investigated IP address belongs to {abuseipdb_data.get("isp")}.

Usage Type:
{abuseipdb_data.get("usage_type")}

An Abuse Confidence Score of {abuseipdb_data.get("abuse_confidence")}% indicates the level of abuse activity reported for this IP address in AbuseIPDB.

If the IP belongs to a CDN or reverse proxy provider, the absence of abuse reports does not necessarily mean the original URL is safe. In such cases, the CDN IP may hide the real origin infrastructure.

Evidence Summary
------------------------------------------------------------

- Abuse Confidence Score : {abuseipdb_data.get("abuse_confidence")}%
- Total Abuse Reports    : {abuseipdb_data.get("total_reports")}
- Distinct Reporters     : {abuseipdb_data.get("distinct_users")}
- Hosting Provider       : {abuseipdb_data.get("isp")}
- Usage Type             : {abuseipdb_data.get("usage_type")}
- Whitelisted            : {abuseipdb_data.get("is_whitelisted")}
- TOR Exit Node          : {abuseipdb_data.get("is_tor")}
- Public IP              : {abuseipdb_data.get("is_public")}
- Last Reported          : {abuseipdb_data.get("last_reported")}

============================================================
END OF ABUSEIPDB REPORT
============================================================
"""

    return report
