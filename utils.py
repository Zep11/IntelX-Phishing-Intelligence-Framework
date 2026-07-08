import os

def create_report_folders():
    folders = [
        "reports/raw_rprt/virustotal",
        "reports/raw_rprt/urlscan",
        "reports/raw_rprt/abuseipdb",
        "reports/raw_rprt/whoislookup",
        "reports/raw_rprt/phishtank",
        "reports/clean_rprt/virustotal",
        "reports/clean_rprt/urlscan",
        "reports/clean_rprt/abuseipdb",
        "reports/clean_rprt/whoislookup",
        "reports/clean_rprt/phishtank"
    ]

    for folder in folders:
        os.makedirs(folder, exist_ok=True)