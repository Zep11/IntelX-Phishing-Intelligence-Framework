# Report_Generator/incident_report.py

import os
from datetime import datetime
from typing import Any


def _display(value: Any, default: str = "Not available") -> str:
    """
    Convert missing or complex values into report-friendly text.
    """
    if value is None or value == "":
        return default

    if isinstance(value, bool):
        return "Yes" if value else "No"

    if isinstance(value, dict):
        if not value:
            return default

        return ", ".join(
            f"{key}: {item}"
            for key, item in value.items()
        )

    if isinstance(value, list):
        if not value:
            return default

        return ", ".join(str(item) for item in value)

    return str(value)


def _append_list_section(
    report: list[str],
    title: str,
    items: Any,
    empty_message: str = "No information available.",
) -> None:
    """
    Add a numbered list section to the report.
    """
    report.append("")
    report.append(title)
    report.append("-" * len(title))

    if not isinstance(items, list) or not items:
        report.append(empty_message)
        return

    for index, item in enumerate(items, start=1):
        report.append(f"{index}. {item}")


def _build_analyst_conclusion(
    risk_data: dict,
    vt_data: dict,
    urlscan_data: dict,
    abuse_data: dict,
    whois_data: dict,
    gsb_data: dict,
) -> str:
    """
    Create the final analyst conclusion using correlated evidence.
    """
    score = int(risk_data.get("risk_score", 0) or 0)
    verdict = risk_data.get(
        "verdict",
        "No Strong Threat Evidence",
    )
    confidence = int(risk_data.get("confidence", 0) or 0)

    supporting_sources = []

    if (
        vt_data.get("malicious", 0) > 0
        or vt_data.get("suspicious", 0) > 0
    ):
        supporting_sources.append("VirusTotal")

    if (
        str(urlscan_data.get("verdict", "")).lower()
        == "malicious"
    ):
        supporting_sources.append("URLScan.io")

    if abuse_data.get("abuse_confidence", 0) > 0:
        supporting_sources.append("AbuseIPDB")

    if gsb_data.get("detected") is True:
        supporting_sources.append("Google Safe Browsing")

    domain_age = risk_data.get("domain_age_days")

    if domain_age is not None and domain_age <= 90:
        supporting_sources.append("WHOIS")

    source_text = (
        ", ".join(supporting_sources)
        if supporting_sources
        else "none of the consulted providers"
    )

    if score >= 80:
        assessment = (
            "The investigated URL demonstrates multiple strong and "
            "independent characteristics associated with phishing or "
            "malicious web activity. Immediate defensive action is advised."
        )
    elif score >= 60:
        assessment = (
            "The investigated URL presents substantial threat indicators. "
            "The URL should be blocked or quarantined until an analyst "
            "completes additional validation."
        )
    elif score >= 35:
        assessment = (
            "The investigated URL contains suspicious characteristics, "
            "but the available evidence is not fully conclusive. The URL "
            "should not be trusted without further investigation."
        )
    elif score >= 15:
        assessment = (
            "The investigation identified limited risk indicators. "
            "Continued caution and monitoring are recommended."
        )
    else:
        assessment = (
            "No strong threat evidence was identified during this "
            "investigation. This result does not guarantee that the URL "
            "is safe, especially if it is newly created or not yet known "
            "to threat-intelligence providers."
        )

    return (
        f"The Risk Engine assigned a score of {score}/100, resulting in "
        f"the verdict '{verdict}' with {confidence}% confidence. "
        f"Positive risk evidence was contributed by {source_text}. "
        f"{assessment}"
    )


def generate_incident_report(
    target_url: str,
    parsed_data: dict,
    static_data: dict,
    vt_data: dict,
    urlscan_data: dict,
    abuse_data: dict,
    whois_data: dict,
    gsb_data: dict,
    risk_data: dict,
    output_path: str = (
        "reports/final_report/incident_report.txt"
    ),
) -> str:
    """
    Generate and save the final consolidated incident report.

    Returns:
        The path of the generated report.
    """

    # Protect against None or malformed provider results.
    parsed_data = (
        parsed_data if isinstance(parsed_data, dict) else {}
    )
    static_data = (
        static_data if isinstance(static_data, dict) else {}
    )
    vt_data = vt_data if isinstance(vt_data, dict) else {}
    urlscan_data = (
        urlscan_data
        if isinstance(urlscan_data, dict)
        else {}
    )
    abuse_data = (
        abuse_data if isinstance(abuse_data, dict) else {}
    )
    whois_data = (
        whois_data if isinstance(whois_data, dict) else {}
    )
    gsb_data = (
        gsb_data if isinstance(gsb_data, dict) else {}
    )
    risk_data = (
        risk_data if isinstance(risk_data, dict) else {}
    )

    os.makedirs(
        os.path.dirname(output_path),
        exist_ok=True,
    )

    generated_at = datetime.now().astimezone().strftime(
        "%Y-%m-%d %H:%M:%S %Z"
    )

    report = []

    report.extend([
        "=" * 72,
        "            PHISHING URL INCIDENT INVESTIGATION REPORT",
        "=" * 72,
        "",
        "CASE INFORMATION",
        "-" * 72,
        f"Target URL          : {_display(target_url)}",
        f"Investigation Time  : {generated_at}",
        f"Overall Risk Score  : "
        f"{_display(risk_data.get('risk_score'))}/100",
        f"Overall Verdict     : "
        f"{_display(risk_data.get('verdict'))}",
        f"Confidence          : "
        f"{_display(risk_data.get('confidence'))}%",
        f"Recommendation      : "
        f"{_display(risk_data.get('recommendation'))}",
    ])

    # ========================================================
    # Parsed URL
    # ========================================================

    report.extend([
        "",
        "=" * 72,
        "1. PARSED URL INFORMATION",
        "=" * 72,
        "",
        f"Scheme              : "
        f"{_display(parsed_data.get('scheme'))}",
        f"Domain              : "
        f"{_display(parsed_data.get('domain'))}",
        f"Hostname            : "
        f"{_display(parsed_data.get('hostname'))}",
        f"Subdomain           : "
        f"{_display(parsed_data.get('subdomain'))}",
        f"Port                : "
        f"{_display(parsed_data.get('port'))}",
        f"Path                : "
        f"{_display(parsed_data.get('path'))}",
        f"Query               : "
        f"{_display(parsed_data.get('query'))}",
        f"IP-Based Hostname   : "
        f"{_display(parsed_data.get('is_ip'))}",
    ])

    # ========================================================
    # Static analysis
    # ========================================================

    report.extend([
        "",
        "=" * 72,
        "2. STATIC URL ANALYSIS",
        "=" * 72,
        "",
        f"URL Length          : "
        f"{_display(static_data.get('url_length'))}",
        f"Long URL            : "
        f"{_display(static_data.get('is_long_url'))}",
        f"'@' Symbol          : "
        f"{_display(static_data.get('has_at_symbol'))}",
        f"IP Hostname         : "
        f"{_display(static_data.get('is_ip_hostname'))}",
        f"Suspicious Keywords : "
        f"{_display(static_data.get('suspicious_keywords'))}",
        f"Insecure HTTP       : "
        f"{_display(static_data.get('uses_http'))}",
        f"Punycode Detected   : "
        f"{_display(static_data.get('punycode_detected'))}",
        f"URL Shortener       : "
        f"{_display(static_data.get('shortener_detected'))}",
        f"Subdomain Count     : "
        f"{_display(static_data.get('subdomain_count'))}",
        f"Non-Standard Port   : "
        f"{_display(static_data.get('non_standard_port'))}",
    ])

    _append_list_section(
        report,
        "Static Analysis Findings",
        static_data.get("findings", []),
        "No static-analysis warnings were recorded.",
    )

    # ========================================================
    # VirusTotal
    # ========================================================

    report.extend([
        "",
        "=" * 72,
        "3. VIRUSTOTAL INTELLIGENCE",
        "=" * 72,
        "",
        f"Verdict             : "
        f"{_display(vt_data.get('verdict'))}",
        f"Final URL           : "
        f"{_display(vt_data.get('final_url'))}",
        f"Page Title          : "
        f"{_display(vt_data.get('title'))}",
        f"Malicious           : "
        f"{_display(vt_data.get('malicious'), '0')}",
        f"Suspicious          : "
        f"{_display(vt_data.get('suspicious'), '0')}",
        f"Harmless            : "
        f"{_display(vt_data.get('harmless'), '0')}",
        f"Undetected          : "
        f"{_display(vt_data.get('undetected'), '0')}",
        f"Detection Ratio     : "
        f"{_display(vt_data.get('vendors_detected'), '0')}"
        f"/{_display(vt_data.get('total_vendors'), '0')}",
        f"Threat Names        : "
        f"{_display(vt_data.get('threat_names'))}",
        f"Targeted Brand      : "
        f"{_display(vt_data.get('targeted_brand'))}",
        f"Categories          : "
        f"{_display(vt_data.get('categories'))}",
        f"Reputation          : "
        f"{_display(vt_data.get('reputation'))}",
        f"Times Submitted     : "
        f"{_display(vt_data.get('times_submitted'))}",
        f"HTTP Content SHA256 : "
        f"{_display(vt_data.get('http_content_sha256'))}",
    ])

    _append_list_section(
        report,
        "VirusTotal Redirect Chain",
        vt_data.get("redirection_chain", []),
        "No VirusTotal redirects were reported.",
    )

    report.append("")
    report.append("Malicious / Suspicious Vendor Detections")
    report.append("-" * 42)

    vendors = vt_data.get("vendors", [])

    if isinstance(vendors, list) and vendors:
        for vendor in vendors:
            if isinstance(vendor, dict):
                report.append(
                    f"- {_display(vendor.get('vendor'))}: "
                    f"{_display(vendor.get('category'))} — "
                    f"{_display(vendor.get('result'))}"
                )
    else:
        report.append(
            "No malicious or suspicious vendor detections "
            "were included."
        )

    # ========================================================
    # URLScan
    # ========================================================

    report.extend([
        "",
        "=" * 72,
        "4. URLSCAN.IO DYNAMIC ANALYSIS",
        "=" * 72,
        "",
        f"Verdict             : "
        f"{_display(urlscan_data.get('verdict'))}",
        f"Submitted URL       : "
        f"{_display(urlscan_data.get('submitted_url'))}",
        f"Final URL           : "
        f"{_display(urlscan_data.get('final_url'))}",
        f"Page Title          : "
        f"{_display(urlscan_data.get('page_title'))}",
        f"Brand Detected      : "
        f"{_display(urlscan_data.get('brand'))}",
        f"Page Domain         : "
        f"{_display(urlscan_data.get('page_domain'))}",
        f"Apex Domain         : "
        f"{_display(urlscan_data.get('apex_domain'))}",
        f"Page IP             : "
        f"{_display(urlscan_data.get('page_ip'))}",
        f"Page ASN            : "
        f"{_display(urlscan_data.get('page_asn'))}",
        f"ASN Owner           : "
        f"{_display(urlscan_data.get('page_asn_name'))}",
        f"Server              : "
        f"{_display(urlscan_data.get('page_server'))}",
        f"Status Code         : "
        f"{_display(urlscan_data.get('page_status'))}",
        f"Domain Age          : "
        f"{_display(urlscan_data.get('domain_age_days'))} days",
        f"TLS Issuer          : "
        f"{_display(urlscan_data.get('tls_issuer'))}",
        f"TLS Age             : "
        f"{_display(urlscan_data.get('tls_age_days'))} days",
        f"Engine Score        : "
        f"{_display(urlscan_data.get('engines_score'))}",
        f"Engine Malicious    : "
        f"{_display(urlscan_data.get('engines_malicious'))}",
        f"Requests Captured   : "
        f"{_display(urlscan_data.get('requests_count'))}",
        f"URLScan Report      : "
        f"{_display(urlscan_data.get('report_url'))}",
        f"Screenshot          : "
        f"{_display(urlscan_data.get('screenshot_url'))}",
    ])

    redirects = urlscan_data.get("redirects", [])
    report.append("")
    report.append("URLScan Redirect Chain")
    report.append("-" * 22)

    if isinstance(redirects, list) and redirects:
        for index, redirect in enumerate(
            redirects,
            start=1,
        ):
            if isinstance(redirect, dict):
                report.append(
                    f"{index}. "
                    f"{_display(redirect.get('status'))}: "
                    f"{_display(redirect.get('from'))} -> "
                    f"{_display(redirect.get('to'))}"
                )
            else:
                report.append(f"{index}. {redirect}")
    else:
        report.append("No redirects were observed.")

    _append_list_section(
        report,
        "Observed IP Addresses",
        urlscan_data.get("observed_ips", []),
        "No observed IP addresses were returned.",
    )

    _append_list_section(
        report,
        "Observed Domains",
        urlscan_data.get("observed_domains", []),
        "No observed domains were returned.",
    )

    report.append("")
    report.append("Detected Technologies")
    report.append("-" * 21)

    technologies = urlscan_data.get("technologies", [])

    if isinstance(technologies, list) and technologies:
        for index, technology in enumerate(
            technologies,
            start=1,
        ):
            if isinstance(technology, dict):
                report.append(
                    f"{index}. "
                    f"{_display(technology.get('name'))}"
                )
                report.append(
                    f"   Confidence : "
                    f"{_display(technology.get('confidence'))}"
                )
                report.append(
                    f"   Categories : "
                    f"{_display(technology.get('categories'))}"
                )
            else:
                report.append(f"{index}. {technology}")
    else:
        report.append("No technologies were detected.")

    # ========================================================
    # AbuseIPDB
    # ========================================================

    report.extend([
        "",
        "=" * 72,
        "5. ABUSEIPDB IP REPUTATION",
        "=" * 72,
        "",
        f"IP Address          : "
        f"{_display(abuse_data.get('ip_address'))}",
        f"Verdict             : "
        f"{_display(abuse_data.get('verdict'))}",
        f"Abuse Confidence    : "
        f"{_display(abuse_data.get('abuse_confidence'), '0')}%",
        f"Country             : "
        f"{_display(abuse_data.get('country'))}",
        f"ISP                 : "
        f"{_display(abuse_data.get('isp'))}",
        f"Provider Domain     : "
        f"{_display(abuse_data.get('domain'))}",
        f"Usage Type          : "
        f"{_display(abuse_data.get('usage_type'))}",
        f"Public IP           : "
        f"{_display(abuse_data.get('is_public'))}",
        f"Whitelisted         : "
        f"{_display(abuse_data.get('is_whitelisted'))}",
        f"TOR Exit Node       : "
        f"{_display(abuse_data.get('is_tor'))}",
        f"Total Reports       : "
        f"{_display(abuse_data.get('total_reports'), '0')}",
        f"Distinct Reporters  : "
        f"{_display(abuse_data.get('distinct_users'), '0')}",
        f"Last Reported       : "
        f"{_display(abuse_data.get('last_reported'))}",
    ])

    _append_list_section(
        report,
        "Associated Hostnames",
        abuse_data.get("hostnames", []),
        "No associated hostnames were returned.",
    )

    if any(
        term in str(
            abuse_data.get("usage_type", "")
        ).lower()
        for term in ["content delivery", "cdn"]
    ):
        report.extend([
            "",
            "Analyst Note",
            "------------",
            (
                "The investigated IP belongs to a CDN or reverse-proxy "
                "provider. A low AbuseIPDB score for this address does not "
                "prove that the investigated URL is safe because the true "
                "origin infrastructure may be concealed behind the provider."
            ),
        ])

    # ========================================================
    # WHOIS
    # ========================================================

    report.extend([
        "",
        "=" * 72,
        "6. WHOIS DOMAIN INTELLIGENCE",
        "=" * 72,
        "",
        f"Domain Name         : "
        f"{_display(whois_data.get('domain_name'))}",
        f"Registrar           : "
        f"{_display(whois_data.get('registrar'))}",
        f"WHOIS Server        : "
        f"{_display(whois_data.get('whois_server'))}",
        f"Organization        : "
        f"{_display(whois_data.get('org'))}",
        f"Country             : "
        f"{_display(whois_data.get('country'))}",
        f"Creation Date       : "
        f"{_display(whois_data.get('creation_date'))}",
        f"Updated Date        : "
        f"{_display(whois_data.get('updated_date'))}",
        f"Expiration Date     : "
        f"{_display(whois_data.get('expiration_date'))}",
        f"Calculated Age      : "
        f"{_display(risk_data.get('domain_age_days'))} days",
        f"DNSSEC              : "
        f"{_display(whois_data.get('dnssec'))}",
        f"Status              : "
        f"{_display(whois_data.get('status'))}",
    ])

    _append_list_section(
        report,
        "WHOIS Name Servers",
        whois_data.get("name_servers", []),
        "No name-server information was returned.",
    )

    _append_list_section(
        report,
        "WHOIS Contact Emails",
        whois_data.get("emails", []),
        "No WHOIS contact emails were returned.",
    )

    # ========================================================
    # Google Safe Browsing
    # ========================================================

    report.extend([
        "",
        "=" * 72,
        "7. GOOGLE SAFE BROWSING",
        "=" * 72,
        "",
        f"Verdict             : "
        f"{_display(gsb_data.get('verdict'))}",
        f"Detected            : "
        f"{_display(gsb_data.get('detected'))}",
        f"Threat Matches      : "
        f"{_display(gsb_data.get('matches_count'), '0')}",
    ])

    matches = gsb_data.get("matches", [])

    report.append("")
    report.append("Google Threat Matches")
    report.append("-" * 21)

    if isinstance(matches, list) and matches:
        for index, match in enumerate(matches, start=1):
            if not isinstance(match, dict):
                report.append(f"{index}. {match}")
                continue

            report.append(
                f"{index}. Threat Type: "
                f"{_display(match.get('threatType'))}"
            )
            report.append(
                f"   Platform: "
                f"{_display(match.get('platformType'))}"
            )
            report.append(
                f"   Entry Type: "
                f"{_display(match.get('threatEntryType'))}"
            )
            report.append(
                f"   Matched URL: "
                f"{_display(match.get('threat', {}).get('url'))}"
            )
    else:
        report.append(
            "No Google Safe Browsing threat-list match was returned."
        )

    # ========================================================
    # Risk Engine
    # ========================================================

    report.extend([
        "",
        "=" * 72,
        "8. RISK-ENGINE CORRELATION",
        "=" * 72,
        "",
        f"Risk Score          : "
        f"{_display(risk_data.get('risk_score'))}/100",
        f"Verdict             : "
        f"{_display(risk_data.get('verdict'))}",
        f"Confidence          : "
        f"{_display(risk_data.get('confidence'))}%",
        f"Recommendation      : "
        f"{_display(risk_data.get('recommendation'))}",
        f"Domain Age          : "
        f"{_display(risk_data.get('domain_age_days'))} days",
    ])

    report.append("")
    report.append("Provider Score Breakdown")
    report.append("-" * 24)

    score_breakdown = risk_data.get(
        "score_breakdown",
        {},
    )

    if isinstance(score_breakdown, dict):
        for provider, points in score_breakdown.items():
            provider_name = (
                str(provider)
                .replace("_", " ")
                .title()
            )

            report.append(
                f"{provider_name:<28}: +{points}"
            )

    _append_list_section(
        report,
        "Positive Risk Evidence",
        risk_data.get("evidence", []),
        "No positive risk evidence was recorded.",
    )

    _append_list_section(
        report,
        "Additional Investigative Context",
        risk_data.get(
            "informational_findings",
            [],
        ),
        "No additional contextual findings were recorded.",
    )

    report.append("")
    report.append("Provider Availability")
    report.append("-" * 21)

    provider_status = risk_data.get(
        "provider_status",
        {},
    )

    if isinstance(provider_status, dict):
        for provider, available in provider_status.items():
            provider_name = (
                str(provider)
                .replace("_", " ")
                .title()
            )

            report.append(
                f"{provider_name:<28}: "
                f"{'Available' if available else 'Unavailable'}"
            )

    # ========================================================
    # Final conclusion
    # ========================================================

    conclusion = _build_analyst_conclusion(
        risk_data,
        vt_data,
        urlscan_data,
        abuse_data,
        whois_data,
        gsb_data,
    )

    report.extend([
        "",
        "=" * 72,
        "9. FINAL ANALYST CONCLUSION",
        "=" * 72,
        "",
        conclusion,
        "",
        "Recommended Action",
        "------------------",
        _display(risk_data.get("recommendation")),
        "",
        "Investigation Limitations",
        "-------------------------",
        (
            "Threat-intelligence results represent the information "
            "available at investigation time. A URL that is not listed "
            "by a provider may still be malicious, newly deployed, "
            "short-lived, geographically restricted, or hidden behind "
            "CDN and reverse-proxy infrastructure. This result does not guarantee that the URL is safe. "
            "Newly deployed or recently reported phishing URLs may not yet appear in VirusTotal, "
            "Google Safe Browsing, URLScan, or AbuseIPDB."
        ),
        "",
        "=" * 72,
        "                      END OF INCIDENT REPORT",
        "=" * 72,
        "",
    ])

    with open(
        output_path,
        "w",
        encoding="utf-8",
    ) as file:
        file.write("\n".join(report))

    return output_path


