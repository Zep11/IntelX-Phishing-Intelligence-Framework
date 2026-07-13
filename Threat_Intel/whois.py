import whois
import json

def whois_lookup(domain):
    if not domain:
        return{
            "status" : "No Domain Provided "

        }
    
    try:
        result = whois.whois(domain)
        raw_result = dict(result)
        with open("reports/raw_rprt/whoislookup/whois_raw_rprt.json", "w", encoding="utf-8") as file:
            json.dump(raw_result, file, indent=4, default=str)

        whois_data = parse_whois_data(raw_result)

        report = generate_whois_report(whois_data)

        with open("reports/clean_rprt/whoislookup/whois_clean_report.txt", "w", encoding="utf-8") as file:
            file.write(report)

        return whois_data

    except Exception as error:
        return {
            "status": "Error",
            "message": str(error)
        }
    
def normalize_whois_value(value):
    if isinstance(value, list):
        return [str(item) for item in value]
    return str(value) if value is not None else None


def parse_whois_data(raw_result):
    creation_date = normalize_whois_value(raw_result.get("creation_date"))
    expiration_date = normalize_whois_value(raw_result.get("expiration_date"))
    updated_date = normalize_whois_value(raw_result.get("updated_date"))

    name_servers = raw_result.get("name_servers", [])
    emails = raw_result.get("emails", [])

    if isinstance(name_servers, str):
        name_servers = [name_servers]

    if isinstance(emails, str):
        emails = [emails]

    whois_data = {
        "domain_name": normalize_whois_value(raw_result.get("domain_name")),
        "registrar": raw_result.get("registrar"),
        "registrant_phone": raw_result.get("registrant_phone"),
        "whois_server": raw_result.get("whois_server"),
        "creation_date": creation_date,
        "expiration_date": expiration_date,
        "updated_date": updated_date,
        "name_servers": name_servers,
        "emails": emails,
        "status": raw_result.get("status"),
        "org": raw_result.get("org"),
        "country": raw_result.get("country"),
        "dnssec": raw_result.get("dnssec"),
    }

    return whois_data
    
def generate_whois_report(whois_data):
    report = f"""
============================================================
                    WHOIS DOMAIN REPORT
============================================================

Domain Summary
--------------
Domain Name      : {whois_data.get("domain_name")}
Registrar        : {whois_data.get("registrar")}
Registration Phone  : {whois_data.get("registrant_phone")}
WHOIS Server     : {whois_data.get("whois_server")}
Organization     : {whois_data.get("org")}
Country          : {whois_data.get("country")}

Registration Dates
------------------
Creation Date    : {whois_data.get("creation_date")}
Updated Date     : {whois_data.get("updated_date")}
Expiration Date  : {whois_data.get("expiration_date")}

Security / Status
-----------------
DNSSEC           : {whois_data.get("dnssec")}
Status           : {whois_data.get("status")}

Name Servers
------------
"""

    for ns in whois_data.get("name_servers", []):
        report += f"- {ns}\n"

    report += "\nContact Emails\n--------------\n"

    for email in whois_data.get("emails", []):
        report += f"- {email}\n"

    report += f"""

Evidence Summary
------------------------------------------------------------

- Domain Registrar     : {whois_data.get("registrar")}
- Domain Creation Date : {whois_data.get("creation_date")}
- Domain Expiry Date   : {whois_data.get("expiration_date")}
- Name Server Count    : {len(whois_data.get("name_servers", []))}
- DNSSEC Status        : {whois_data.get("dnssec")}

============================================================
END OF WHOIS REPORT
============================================================
"""

    return report