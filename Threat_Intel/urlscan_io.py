import requests
import time 
import json

def urlscan_lookup(url , api_keys):
    if not api_keys:
        return{
            "status ": "No API-Key Configured"
        }

    # Endpoint to submit the URL 
    endpoint = "https://urlscan.io/api/v1/scan"

    #Headers to Sent to the Website

    headers = {
        "API-Key": api_keys , 
        "Content-Type": "application/json"
    }

    #Payload/Data to send to the Website 

    payload = {
        "url" : url , 
        "visibility" : "public"
    }

    response = requests.post(
        endpoint , headers=headers , json=payload
    )

    #NOW CHECKING THE RESPONSE

    if response.status_code != 200:
        return {
            "status": "Error",
            "code": response.status_code
        }
    
    result= response.json()
    # UUID is being returned out here .
    scan_uuid = result.get("uuid")

    #TEMPORARY 
    print("Please wait ")
    time.sleep(10)

    # Fetch the Complete Scan , calling the fetching function 
    full_result = wait_for_urlscan_result(scan_uuid , api_keys )
    
    #Creating the raw report 
    with open("reports/raw_rprt/urlscan/url_scan_raw_rprt.json", "w" , encoding="utf-8") as file:
        json.dump(full_result, file, indent=4)
    print("[+] URLSCAN clean report saved to reports/raw_rprt/urlscan/urlscan_io.txt")

    urlscan_data = parse_urlscan_data(full_result)

    # Temporary debugging prints
    print("\n========== URLScan Summary ==========")
    print("Verdict      :", urlscan_data.get("verdict"))
    print("Page Title   :", urlscan_data.get("page_title"))
    print("Final URL    :", urlscan_data.get("final_url"))
    print("IP Address   :", urlscan_data.get("page_ip"))
    print("ASN          :", urlscan_data.get("page_asn_name"))
    print("Brand        :", urlscan_data.get("brand"))
    print("=====================================\n")

    report = generate_urlscan_report(urlscan_data)

    with open("reports/clean_rprt/urlscan/urlscan_io.txt", "w", encoding="utf-8") as file:
        file.write(report)
    print("[+] URLSCAN clean report saved to reports/clean_rprt/urlscan/urlscan_io.txt")

    return urlscan_data
    

# fetch the Informations from the UUID . 

def fetch_urls_scan_result(scan_uuid , api_keys ):
    endpoint = f"https://urlscan.io/api/v1/result/{scan_uuid}/"
    headers = {
        "API-Key" : api_keys
    }
    response = requests.get( 
        endpoint , headers=headers
    )
    
    if response.status_code != 200:
        return {
            "status": "Error",
            "code": response.status_code
        }
    return response.json()

# POLLING SECTION TO INCREASE NUMBER OF TRIES 

def wait_for_urlscan_result(scan_uuid, api_key):
    for _ in range(30):  # 30 attempts
        full_result = fetch_urls_scan_result(scan_uuid, api_key)

        if full_result.get("status") != "Error":
            return full_result

        if full_result.get("code") == 404:
            time.sleep(5)
            continue

        return full_result

    return {
        "status": "Timeout",
        "message": "URLScan result was not ready in time."
    }

# Data parsing 
def parse_urlscan_data(full_result):
    task = full_result.get("task", {})
    page = full_result.get("page", {})
    lists = full_result.get("lists", {})
    data = full_result.get("data", {})
    verdicts = full_result.get("verdicts", {})
    meta = full_result.get("meta", {})

    overall_verdict = verdicts.get("overall", {})
    engines_verdict = verdicts.get("engines", {})
    urlscan_verdict = verdicts.get("urlscan", {})
    community_verdict = verdicts.get("community", {})

    technologies = []
    wappa_data = (
        meta.get("processors", {})
        .get("wappa", {})
        .get("data", [])
    )

    for tech in wappa_data:
        technologies.append({
            "name": tech.get("app"),
            "website": tech.get("website"),
            "confidence": tech.get("confidenceTotal"),
            "categories": [
                category.get("name")
                for category in tech.get("categories", [])
            ]
        })

    if engines_verdict.get("malicious"):
        verdict = "Malicious"
    elif overall_verdict.get("malicious"):
        verdict = "Malicious"
    elif urlscan_verdict.get("malicious"):
        verdict = "Malicious"
    else:
        verdict = "Clean"

    urlscan_data = {
        "submitted_url": task.get("url"),
        "final_url": page.get("url"),
        "page_title": page.get("title"),

        "page_domain": page.get("domain"),
        "apex_domain": page.get("apexDomain"),
        "domain_age_days": page.get("domainAgeDays"),
        "apex_domain_age_days": page.get("apexDomainAgeDays"),

        "page_ip": page.get("ip"),
        "page_asn": page.get("asn"),
        "page_asn_name": page.get("asnname"),
        "page_server": page.get("server"),
        "status": page.get("status"),
        "page_country": page.get("country"),

        "tls_issuer": page.get("tlsIssuer"),
        "tls_age_days": page.get("tlsAgeDays"),
        "tls_valid_days": page.get("tlsValidDays"),
        "tls_valid_from": page.get("tlsValidFrom"),

        "report_url": task.get("reportURL"),
        "screenshot_url": task.get("screenshotURL"),
        "dom_url": task.get("domURL"),
        "uuid": task.get("uuid"),

        "redirects": data.get("redirects", []),

        "observed_ips": lists.get("ips", []),
        "countries": lists.get("countries", []),
        "observed_asns": lists.get("asns", []),
        "observed_domains": lists.get("domains", []),
        "observed_servers": lists.get("servers", []),
        "urls": lists.get("urls", []),
        "certificates": lists.get("certificates", []),
        "hashes": lists.get("hashes", []),

        "technologies": technologies,

        "verdict": verdict,
        "overall_score": overall_verdict.get("score"),
        "overall_malicious": overall_verdict.get("malicious"),
        "urlscan_score": urlscan_verdict.get("score"),
        "urlscan_malicious": urlscan_verdict.get("malicious"),
        "engines_score": engines_verdict.get("score"),
        "engines_malicious": engines_verdict.get("malicious"),
        "engine_tags": engines_verdict.get("tags", []),

        "community_score": community_verdict.get("score"),
        "community_votes_total": community_verdict.get("votesTotal"),
        "community_votes_malicious": community_verdict.get("votesMalicious"),
        "community_votes_benign": community_verdict.get("votesBenign"),

        "brand": full_result.get("visible", {}).get("brandname"),

        "requests_count": len(data.get("requests", [])),
        "console_errors": data.get("console", []),
    }

    return urlscan_data

#Generating the Clean individual report 

def safe(value, default="N/A"):
    return value if value not in [None, "", [], {}] else default


def format_list(items, default="None observed"):
    if not items:
        return default
    return "\n".join(f"{i}. {item}" for i, item in enumerate(items, 1))


def generate_urlscan_report(urlscan_data):
    redirects_text = ""

    redirects = urlscan_data.get("redirects", [])
    if redirects:
        for redirect in redirects:
            redirects_text += (
                f'{safe(redirect.get("status"))} : '
                f'{safe(redirect.get("from"))} -> '
                f'{safe(redirect.get("to"))}\n'
            )
    else:
        redirects_text = "No redirects observed.\n"

    technologies_text = ""

    technologies = urlscan_data.get("technologies", [])
    if technologies:
        for index, tech in enumerate(technologies, start=1):
            if isinstance(tech, dict):
                technologies_text += f"{index}. {safe(tech.get('name'))}\n"
                technologies_text += f"   Website    : {safe(tech.get('website'))}\n"
                technologies_text += f"   Confidence : {safe(tech.get('confidence'))}\n"
                technologies_text += (
                    f"   Categories : {', '.join(tech.get('categories', [])) or 'N/A'}\n\n"
                )
            else:
                technologies_text += f"{index}. {safe(tech)}\n"
    else:
        technologies_text = "No technologies detected.\n"

    report = f"""
============================================================
             URLSCAN.IO THREAT ANALYSIS REPORT
============================================================

Scan Summary
------------
Submitted URL      : {urlscan_data.get("submitted_url")}
Final URL          : {urlscan_data.get("final_url")}
Page Title         : {urlscan_data.get("page_title")}
Verdict            : {urlscan_data.get("verdict")}
Overall Score      : {urlscan_data.get("overall_score")}
Engine Score       : {urlscan_data.get("engines_score")}
Brand Targeted     : {urlscan_data.get("brand")}

------------------------------------------------------------
 Page Network Information
------------------------------------------------------------

IP Address         : {urlscan_data.get("page_ip")}
Country            : {urlscan_data.get("page_country")}   
ASN                : {urlscan_data.get("page_asn")}
ASN Name           : {urlscan_data.get("page_asn_name")}
Server             : {urlscan_data.get("page_server")}

------------------------------------------------------------
Page Domain Information
------------------------------------------------------------

Domain             : {urlscan_data.get("page_domain")}
Apex Domain        : {urlscan_data.get("apex_domain")}
Domain Age         : {urlscan_data.get("domain_age_days")}
Certificate Issuer : {urlscan_data.get("tls_issuer")}
Certificate Validity : {urlscan_data.get("tls_validity_days")}

------------------------------------------------------------
Browser Behaviour
------------------------------------------------------------

Redirect Chain
---------------  

{redirects_text}
------------------------------------------------------------
Detected Technologies
------------------------------------------------------------

{technologies_text}


------------------------------------------------------------
Threat Intelligence
------------------------------------------------------------

Overall Verdict : {urlscan_data.get("overall_verdict")}

URLScan Verdict : {urlscan_data.get("urlscan_verdict")}

Community Verdict : {urlscan_data.get("community_verdict")}

Engine Verdict  : {urlscan_data.get("engines_verdict")}



------------------------------------------------------------
Indicators of Compromise (IOCs)
------------------------------------------------------------

IPs Observed : {urlscan_data.get("observed_ips")}

Domains Observed : {urlscan_data.get("overserved_domains")}

Certificates : {urlscan_data.get("certificates")}

Hashes : {urlscan_data.get("hashes")}

------------------------------------------------------------
Evidence Summary
------------------------------------------------------------
- URLScan verdict: {urlscan_data.get("verdict")}
- Engine malicious: {urlscan_data.get("engines_malicious")}
- Engine score: {urlscan_data.get("engines_score")}
- Brand detected: {urlscan_data.get("brand")}
- Domain age: {urlscan_data.get("domain_age_days")} days
- TLS age: {urlscan_data.get("tls_age_days")} days
- Redirects observed: {len(urlscan_data.get("redirects", []))}
- Domains contacted: {len(urlscan_data.get("observed_domains", []))}
- IPs observed: {len(urlscan_data.get("observed_ips", []))}
- Requests captured: {urlscan_data.get("requests_count")}

============================================================
END OF REPORT
============================================================
"""
    return report