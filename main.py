from validator import valid_url
from parser import parse_url
from signals import check_url_length
from signals import checking_at_symbol
from signals import sus_key
from signals import http_check
from signals import punnycode_check
from signals import url_shorteners
from signals import subd_check
from signals import port_check
from config  import (check_config, setup_config , load_config , api_check)
from Threat_Intel.virus_total import virustotal_lookup
from Threat_Intel.urlscan_io import urlscan_lookup 
from Threat_Intel.abuseipdb import abuseipdb_lookup
from Threat_Intel.whois import whois_lookup
from Threat_Intel.google_safe import google_safe_browsing_lookup
from Risk_Engine.risk_engine import calculate_risk
from report_gen.incident_rep import (generate_incident_report)
from utils import create_report_folders
create_report_folders()                                      #Instantly Create Folders for reports

#UI/UX SECTION 
from uiux import (
    console,
    show_banner,
    get_target_url,
    ask_yes_no,
    show_api_loading,
    run_with_spinner,
    show_target_url,
    show_parsed_url_animated,
    show_section,
    show_signal,
    show_risk_summary,
    show_report_locations,
    show_completion_message,
    show_error,
    show_warning,
)


#Checking for Configuration and LOADING 
def load_or_setup_configuration():
    """
    Load API configuration.

    If the configuration file does not exist, start setup.
    If it exists but contains no API keys, ask whether the user
    wants to configure them.
    """

    if not check_config():
        setup_config()

    api_keys = load_config()

    if not api_check(api_keys):
        should_configure = ask_yes_no(
            "No threat-intelligence API keys are configured. "
            "Would you like to configure them now? (Y/N)"
        )

        if should_configure:
            setup_config()
            api_keys = load_config()

    return api_keys    


# FETCHING THE URL 
def get_url():
    url = input("\nEnter a URL\n > ").strip().lower()
    return url



def display_static_analysis(user_url, parsed_data):
    """
    Run, display, and return compact static URL findings.
    """

    show_section("STATIC URL INSPECTION")

    # Calculate every signal once
    length_info = check_url_length(user_url)

    has_at_symbol = checking_at_symbol(user_url)

    is_ip_hostname = parsed_data.get("is_ip", False)

    keywords = sus_key(user_url)

    uses_http = bool(
        http_check(parsed_data.get("scheme"))
    )

    has_punycode = bool(
        punnycode_check(
            parsed_data.get("domain", "")
        )
    )

    has_shortener = bool(
        url_shorteners(
            parsed_data.get("domain", "")
        )
    )

    subdomain_count = subd_check(
        parsed_data.get("subdomain", "")
    )

    non_standard_port = bool(
        port_check(
            parsed_data.get("port")
        )
    )

    findings = []

    # URL length
    is_long_url = length_info.get("its_long", False)

    show_signal(
        suspicious=is_long_url,
        suspicious_message="Suspiciously long URL detected.",
        normal_message="URL length appears normal.",
    )

    if is_long_url:
        findings.append(
            "Suspiciously long URL detected."
        )

    # @ symbol
    show_signal(
        suspicious=has_at_symbol,
        suspicious_message="'@' symbol detected in the URL.",
        normal_message="No '@' symbol detected.",
    )

    if has_at_symbol:
        findings.append(
            "The URL contains an '@' symbol."
        )

    # IP-based hostname
    show_signal(
        suspicious=is_ip_hostname,
        suspicious_message="The hostname is an IP address.",
        normal_message="The hostname uses a domain name.",
    )

    if is_ip_hostname:
        findings.append(
            "The hostname directly uses an IP address."
        )

    # Suspicious keywords
    if keywords:
        show_warning(
            f"Suspicious URL keywords detected: {keywords}"
        )

        findings.append(
            f"Suspicious keywords detected: {keywords}"
        )
    else:
        show_signal(
            suspicious=False,
            suspicious_message="",
            normal_message="No suspicious URL keywords detected.",
        )

    # HTTP instead of HTTPS
    show_signal(
        suspicious=uses_http,
        suspicious_message="The URL uses insecure HTTP.",
        normal_message="The URL uses HTTPS.",
    )

    if uses_http:
        findings.append(
            "The URL uses insecure HTTP."
        )

    # Punycode
    show_signal(
        suspicious=has_punycode,
        suspicious_message="Punycode detected in the domain.",
        normal_message="No punycode detected.",
    )

    if has_punycode:
        findings.append(
            "Punycode was detected in the domain."
        )

    # URL shortener
    show_signal(
        suspicious=has_shortener,
        suspicious_message="URL-shortening service detected.",
        normal_message="No URL-shortening service detected.",
    )

    if has_shortener:
        findings.append(
            "A URL-shortening service was detected."
        )

    # Subdomain count
    show_signal(
        suspicious=subdomain_count > 3,
        suspicious_message=(
            f"High subdomain count detected: "
            f"{subdomain_count}."
        ),
        normal_message=(
            f"Subdomain count appears normal: "
            f"{subdomain_count}."
        ),
    )

    if subdomain_count > 3:
        findings.append(
            f"High subdomain count detected: "
        )

    # Port
    show_signal(
        suspicious=non_standard_port,
        suspicious_message=(
            f"Non-standard port detected: "
            f"{parsed_data.get('port')}."
        ),
        normal_message="No non-standard port detected.",
    )

    if non_standard_port:
        findings.append(
            f"Non-standard port detected: "
            f"{parsed_data.get('port')}."
        )

    return {
        "url_length": length_info.get(
            "length",
            len(user_url),
        ),
        "is_long_url": is_long_url,
        "has_at_symbol": has_at_symbol,
        "is_ip_hostname": is_ip_hostname,
        "suspicious_keywords": keywords,
        "uses_http": uses_http,
        "punycode_detected": has_punycode,
        "shortener_detected": has_shortener,
        "subdomain_count": subdomain_count,
        "non_standard_port": non_standard_port,
        "findings": findings,
        "total_static_flags": len(findings),
    }

def main():
    # Create all report folders before analysis starts
    create_report_folders()

    # Temporary URL-input prompt
    user_url = get_target_url()

    # Permanent startup banner
    show_banner()

    # Temporary configuration flow
    api_keys = load_or_setup_configuration()


    vt_key = api_keys.get("vt_key")
    urlscan_key = api_keys.get("urlscan_key")
    abuse_key = api_keys.get("abuse_key")
    gsb_key = api_keys.get("gsb_key")

    # Temporary API loading display
    show_api_loading({
        "VirusTotal": bool(vt_key),
        "URLScan.io": bool(urlscan_key and urlscan_key.strip()),
        "AbuseIPDB": bool(abuse_key),
        "Google Safe Browsing": bool(gsb_key),
        "WHOIS": True,
    })


    if not valid_url(user_url):
        show_error("The supplied URL is invalid.")
        return

    # Parse the URL once
    parsed_data = parse_url(user_url)

    # Permanent target display
    show_target_url(user_url)

    # Printing the Parsed URL
    show_parsed_url_animated(parsed_data)


    # Permanent compact static-analysis output
    static_result = display_static_analysis(user_url,parsed_data)

    # ========================================================
    # THREAT-INTELLIGENCE ANALYSIS
    # ========================================================

    console.print()
    vt_result = run_with_spinner(
        "Running VirusTotal threat analysis...",
        virustotal_lookup,
        user_url,
        vt_key,
    )
        

    urlscan_result = run_with_spinner(
        "Launching URLScan.io browser analysis...",
        urlscan_lookup,
        user_url,
        urlscan_key,
    )

    # Prefer the main page IP returned by URLScan.
    page_ip = urlscan_result.get("page_ip")

    # Fallback to the first observed IP if page_ip is unavailable.
    if not page_ip:
        observed_ips = urlscan_result.get(
            "observed_ips",
            [],
        )

        if observed_ips:
            page_ip = observed_ips[0]

    abuse_result = run_with_spinner(
        "Checking IP reputation with AbuseIPDB...",
        abuseipdb_lookup,
        page_ip,
        abuse_key,
    )

    whois_result = run_with_spinner(
        "Collecting WHOIS registration intelligence...",
        whois_lookup,
        parsed_data.get("domain"),
    )

    gsb_result = run_with_spinner(
        "Checking Google Safe Browsing threat lists...",
        google_safe_browsing_lookup,
        user_url,
        gsb_key,
    )

    # ========================================================
    # RISK CORRELATION
    # ========================================================

    risk_result = run_with_spinner(
        "Correlating threat intelligence and calculating risk...",
        calculate_risk,
        vt_result,
        urlscan_result,
        abuse_result,
        whois_result,
        gsb_result,
    )
    incident_report_path = run_with_spinner(
    "Generating final incident investigation report...",
    generate_incident_report,
    user_url,
    parsed_data,
    static_result,
    vt_result,
    urlscan_result,
    abuse_result,
    whois_result,
    gsb_result,
    risk_result,
    )

    # Permanent final output
    show_risk_summary(
        risk_result,
        show_breakdown=True,
        show_evidence=True,
        evidence_limit=6,
    )

    # The final incident-report file does not exist yet.
    # We will connect it here after building the report generator.
    show_report_locations(
        final_report_path=(
            incident_report_path),
        raw_reports_path="reports/raw_rprt/",
        clean_reports_path="reports/clean_rprt/",
    )

    show_completion_message()


if __name__ == "__main__":
    main()