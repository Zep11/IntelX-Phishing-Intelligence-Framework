#File to Store all related functions coming threat Intel 

import requests
import time
import json
import base64


def get_url_id(url):
    url_bytes= url.encode()
    encoded_url=base64.urlsafe_b64encode(url_bytes).decode()
    return encoded_url.strip("=")

def fetch_url_details(url , api_key):
    url_id = get_url_id(url)
    endpoint= f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "x-apikey": api_key
    }
    response = requests.get(endpoint, headers=headers)


    if response.status_code != 200:
        return {
            "status": "Error",
            "code": response.status_code
        }
    return response.json()

def virustotal_lookup(url , api_key):
    if not api_key:
        return {
            "status":"No API Key"
        }
    
     # Step 1: Try existing VT report first
    full_result = fetch_url_details(url, api_key)

    if full_result.get("status") != "Error":
        with open("reports/raw_rprt/virustotal/vt_raw_rprt.json", "w" , encoding="utf-8") as file:
            json.dump(full_result, file, indent=4)
        print("[+] VirusTotal full URL response saved to vt_raw_rprt.json")


        vt_data = parse_vt_data(full_result)
        report = generate_vt_report(vt_data)
        with open("reports/clean_rprt/virustotal/vt_clean_report.txt", "w", encoding="utf-8") as file:
            file.write(report)
        print("[+] VirusTotal clean report saved to vt_clean_report.txt")

        return vt_data

    # Step 2: If no existing report, submit URL
    endpoint = "https://www.virustotal.com/api/v3/urls"                        #DEBUG 
    
    headers = {
        "x-apikey" : api_key
    }

    data = {
        "url":url
    }
    
    response= requests.post(endpoint, headers=headers , data=data)
    
    
    if response.status_code!=200:
        return {
            "status":"error", 
            "Code":response.status_code
        } 
    result=response.json()
    analysis_id = result["data"]["id"]

    analysis_endpoint = ( f"https://www.virustotal.com/api/v3/analyses/{analysis_id}")
    #POLLING  
    for _ in range(30):
        analysis_response = requests.get(analysis_endpoint, headers=headers)
    

        if analysis_response.status_code!=200:
            return {
                "status":"Error" ,
                "Code": analysis_response.status_code
             }
        analysis_result = analysis_response.json()
        status = analysis_result["data"]["attributes"]["status"]
        
        

        if status =="completed":
            full_result = fetch_url_details(url, api_key)

            with open("reports/raw_rprt/virustotal/vt_raw_rprt.json", "w" , encoding="utf-8") as file:
                json.dump(full_result, file, indent=4)

            print("[+] VirusTotal full URL response saved to vt_raw_rprt.json")

            vt_data = parse_vt_data(full_result)
            report = generate_vt_report(vt_data)

            with open("reports/clean_rprt/virustotal/vt_clean_report.txt", "w", encoding="utf-8") as file:
                file.write(report)

            print("[+] VirusTotal clean report saved to vt_clean_report.txt")
            
            return vt_data
        
        time.sleep(2)

    print("[DEBUG] Analysis still not completed. Fetching existing URL intelligence...")

    return {
        "status": "Pending",
        "message": "VirusTotal analysis is still processing."
    }
#EXTRACTING INFORMATIONS 

def parse_vt_data(full_result):
    attributes = full_result.get("data", {}).get("attributes", {})

    stats = attributes.get("last_analysis_stats", {})
    results = attributes.get("last_analysis_results", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    timeout = stats.get("timeout", 0)

    vendors = []

    for vendor_name, vendor_data in results.items():
        category = vendor_data.get("category")
        result = vendor_data.get("result")

        if category in ["malicious", "suspicious"]:
            vendors.append({
                "vendor": vendor_name,
                "category": category,
                "result": result
            })

    total_vendors = malicious + suspicious + harmless + undetected + timeout
    vendors_detected = malicious + suspicious

    if malicious > 0:
        verdict = "Malicious"
    elif suspicious > 0:
        verdict = "Suspicious"
    else:
        verdict = "Clean"

    vt_data = {
        "url": attributes.get("url"),
        "final_url": attributes.get("last_final_url"),
        "title": attributes.get("title"),
        "analysis_date": attributes.get("last_analysis_date"),
        "last_submission_date": attributes.get("last_submission_date"),
        "last_modification_date": attributes.get("last_modification_date"),

        "verdict": verdict,
        "categories": attributes.get("categories", {}),
        "web_category": attributes.get("web_category"),
        "threat_names": attributes.get("threat_names", []),
        "targeted_brand": attributes.get("targeted_brand", {}),

        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "timeout": timeout,
        "vendors_detected": vendors_detected,
        "total_vendors": total_vendors,

        "vendors": vendors,

        "reputation": attributes.get("reputation"),
        "votes": attributes.get("total_votes", {}),
        "times_submitted": attributes.get("times_submitted"),

        "redirection_chain": attributes.get("redirection_chain", []),
        "outgoing_links": attributes.get("outgoing_links", []),
        "trackers": attributes.get("trackers", {}),

        "http_content_sha256": attributes.get("last_http_response_content_sha256"),

        "tags": attributes.get("tags", []),
        
    }

    return vt_data

# Generating Report 

def generate_vt_report(vt_data):
    report = f"""
VirusTotal URL Intelligence Report
=================================

URL: {vt_data.get("url")}
Final URL: {vt_data.get("final_url")}
Title: {vt_data.get("title")}

Verdict: {vt_data.get("verdict")}
Category: {vt_data.get("categories")}

Detection Summary
-----------------
Malicious: {vt_data.get("malicious")}
Suspicious: {vt_data.get("suspicious")}
Harmless: {vt_data.get("harmless")}
Undetected: {vt_data.get("undetected")}
Timeout: {vt_data.get("timeout")}

Detection Ratio: {vt_data.get("vendors_detected")} / {vt_data.get("total_vendors")}

Threat Details
--------------
Threat Names: {vt_data.get("threat_names")}
Targeted Brand: {vt_data.get("targeted_brand")}
Web Category: {vt_data.get("web_category")}

Reputation
----------
Reputation: {vt_data.get("reputation")}
Votes: {vt_data.get("votes")}
Times Submitted: {vt_data.get("times_submitted")}

HTTP Content SHA256
-------------------
{vt_data.get("http_content_sha256")}

Redirection Chain
-----------------
"""

    for index, redirect_url in enumerate(vt_data.get("redirection_chain", []), start=1):
        report += f"{index}. {redirect_url}\n"

    report += "\nVendor Detections\n-----------------\n"

    for vendor in vt_data.get("vendors", []):
        report += (
            f"{vendor.get('vendor')}: "
            f"{vendor.get('categories')} - "
            f"{vendor.get('result')}\n"
        )

    return report