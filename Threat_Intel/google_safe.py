import requests 
import json


def google_safe_browsing_lookup(url, api_keys):
    if not api_keys:
        return {
            "status" : "No API Key "
        }
    
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_keys}"

    payload = {
        "client": {
            "clientId": "phishing-url-analyzer",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": [
                "ANY_PLATFORM"
            ],
            "threatEntryTypes": [
                "URL"
            ],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    #All the response are saved in this variable and then parsed to get the required data for the report
    response = requests.post(endpoint, json=payload)


    if response.status_code != 200:
        return {
            "status" : "Error" ,
            "code" : response.status_code,
            "message" : response.text
        }
    
    full_result = response.json()

    with open("reports/raw_rprt/google_safe_browsing/gsb_raw_rprt.json", "w", encoding="utf-8") as file:
        json.dump(full_result, file, indent=4)
    



    gsb_data = parse_gsb_data(full_result , url)

    report = generate_gsb_report(gsb_data)

    #Function to call the function to generate the report and save it in the reports folder

    with open("reports/clean_rprt/google_safe_browsing/gsb_clean_report.txt", "w", encoding="utf-8") as file:
        file.write(report)
    

    return gsb_data

def parse_gsb_data(full_result, url):
    matches = full_result.get("matches", [])

    if matches:
        verdict = "Malicious"
        detected = True
    else:
        verdict = "Clean"
        detected = False

    gsb_data = {
        "url": url,
        "verdict": verdict,
        "detected": detected,
        "matches_count": len(matches),
        "matches": matches
    }

    return gsb_data

# Function to generate a clean report based on the parsed data 
def generate_gsb_report(gsb_data):
    report = f"""
============================================================
            GOOGLE SAFE BROWSING THREAT REPORT
============================================================

Scan Summary
------------
URL              : {gsb_data.get("url")}
Verdict          : {gsb_data.get("verdict")}
Detected         : {gsb_data.get("detected")}
Matches Count    : {gsb_data.get("matches_count")}

Threat Matches
--------------
"""

    matches = gsb_data.get("matches", [])

    if matches:
        for index, match in enumerate(matches, start=1):
            report += f"""
Match {index}
--------
Threat Type       : {match.get("threatType")}
Platform Type     : {match.get("platformType")}
Threat Entry Type : {match.get("threatEntryType")}
Matched URL       : {match.get("threat", {}).get("url")}
Cache Duration    : {match.get("cacheDuration")}
"""
    else:
        report += "No matches found in Google Safe Browsing threat lists.\n"

    report += f"""

Evidence Summary
------------------------------------------------------------

- Google Safe Browsing Verdict : {gsb_data.get("verdict")}
- URL Detected                 : {gsb_data.get("detected")}
- Threat Matches               : {gsb_data.get("matches_count")}

============================================================
END OF GOOGLE SAFE BROWSING REPORT
============================================================
"""

    return report