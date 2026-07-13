from datetime import datetime , timezone

from datetime import datetime, timezone


def _safe_dict(value):
    """Always return a dictionary."""
    return value if isinstance(value, dict) else {}


def _safe_int(value, default=0):
    """Convert a value to int without crashing."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _first_value(value):
    """
    WHOIS fields may be a string, datetime, list, or None.
    Return the first useful value.
    """
    if isinstance(value, list):
        return value[0] if value else None

    return value


def _parse_datetime(value):
    """
    Convert common WHOIS date formats into a datetime object.
    Returns None when the date cannot be understood.
    """
    value = _first_value(value)

    if value is None:
        return None

    if isinstance(value, datetime):
        parsed_date = value
    else:
        text = str(value).strip()

        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d",
            "%d-%b-%Y",
            "%Y.%m.%d",
        ]

        parsed_date = None

        for date_format in formats:
            try:
                parsed_date = datetime.strptime(text, date_format)
                break
            except ValueError:
                continue

        if parsed_date is None:
            try:
                parsed_date = datetime.fromisoformat(
                    text.replace("Z", "+00:00")
                )
            except ValueError:
                return None

    if parsed_date.tzinfo is None:
        parsed_date = parsed_date.replace(tzinfo=timezone.utc)

    return parsed_date


def _calculate_domain_age_days(creation_date):
    """Return domain age in days or None."""
    parsed_date = _parse_datetime(creation_date)

    if parsed_date is None:
        return None

    now = datetime.now(timezone.utc)
    age = (now - parsed_date.astimezone(timezone.utc)).days

    return max(age, 0)


def _provider_available(provider_data):
    """
    Check whether a provider returned useful data instead of an error.
    """
    if not isinstance(provider_data, dict) or not provider_data:
        return False

    status = str(provider_data.get("status", "")).strip().lower()

    unavailable_statuses = {
        "error",
        "no api key",
        "no api-key configured",
        "no domain provided",
        "no ip provided",
        "pending",
        "timeout",
    }

    return status not in unavailable_statuses


def calculate_risk(
    vt_data,
    urlscan_data,
    abuse_data,
    whois_data,
    gsb_data,
):
    """
    Correlate parsed results from all threat-intelligence providers.

    Returns:
        {
            "risk_score": int,
            "verdict": str,
            "confidence": int,
            "recommendation": str,
            "evidence": list,
            "positive_findings": list,
            "informational_findings": list,
            "provider_status": dict,
            "score_breakdown": dict,
            "domain_age_days": int | None
        }
    """

    vt_data = _safe_dict(vt_data)
    urlscan_data = _safe_dict(urlscan_data)
    abuse_data = _safe_dict(abuse_data)
    whois_data = _safe_dict(whois_data)
    gsb_data = _safe_dict(gsb_data)

    risk_score = 0

    evidence = []
    positive_findings = []
    informational_findings = []

    score_breakdown = {
        "virustotal": 0,
        "urlscan": 0,
        "abuseipdb": 0,
        "whois": 0,
        "google_safe_browsing": 0,
    }

    provider_status = {
        "virustotal": _provider_available(vt_data),
        "urlscan": _provider_available(urlscan_data),
        "abuseipdb": _provider_available(abuse_data),
        "whois": _provider_available(whois_data),
        "google_safe_browsing": _provider_available(gsb_data),
    }

    # ========================================================
    # VirusTotal scoring — maximum 35 points
    # ========================================================

    vt_malicious = _safe_int(vt_data.get("malicious"))
    vt_suspicious = _safe_int(vt_data.get("suspicious"))
    vt_detected = vt_malicious + vt_suspicious
    vt_total = _safe_int(vt_data.get("total_vendors"))

    if vt_malicious >= 20:
        points = 35
    elif vt_malicious >= 10:
        points = 30
    elif vt_malicious >= 5:
        points = 22
    elif vt_malicious >= 1:
        points = 12
    elif vt_suspicious >= 1:
        points = 7
    else:
        points = 0

    if points:
        risk_score += points
        score_breakdown["virustotal"] += points

        detection_ratio = (
            f"{vt_detected}/{vt_total}"
            if vt_total
            else str(vt_detected)
        )

        evidence.append(
            f"+{points} VirusTotal: detection ratio "
            f"{detection_ratio}; {vt_malicious} malicious and "
            f"{vt_suspicious} suspicious classifications."
        )

        positive_findings.append(
            f"VirusTotal identified {vt_malicious} malicious and "
            f"{vt_suspicious} suspicious detections."
        )
    elif provider_status["virustotal"]:
        informational_findings.append(
            "VirusTotal did not report malicious or suspicious detections."
        )

    threat_names = vt_data.get("threat_names", [])
    if threat_names:
        informational_findings.append(
            f"VirusTotal threat names: {', '.join(map(str, threat_names))}."
        )

    targeted_brand = vt_data.get("targeted_brand")
    if targeted_brand:
        informational_findings.append(
            f"VirusTotal targeted-brand information: {targeted_brand}."
        )

    # ========================================================
    # Google Safe Browsing — maximum 30 points
    # ========================================================

    if gsb_data.get("detected") is True:
        points = 30
        risk_score += points
        score_breakdown["google_safe_browsing"] += points

        matches = gsb_data.get("matches", [])
        threat_types = sorted({
            str(match.get("threatType"))
            for match in matches
            if isinstance(match, dict) and match.get("threatType")
        })

        threat_description = (
            ", ".join(threat_types)
            if threat_types
            else "a Google threat list"
        )

        evidence.append(
            f"+{points} Google Safe Browsing: URL matched "
            f"{threat_description}."
        )

        positive_findings.append(
            "Google Safe Browsing listed the URL as unsafe."
        )
    elif provider_status["google_safe_browsing"]:
        informational_findings.append(
            "Google Safe Browsing returned no threat-list match."
        )

    # ========================================================
    # URLScan.io — maximum 30 points
    # ========================================================

    urlscan_verdict = str(
        urlscan_data.get("verdict", "")
    ).strip().lower()

    engines_malicious = urlscan_data.get("engines_malicious")
    overall_malicious = urlscan_data.get("overall_malicious")

    if (
        urlscan_verdict == "malicious"
        or engines_malicious is True
        or overall_malicious is True
    ):
        points = 22
        risk_score += points
        score_breakdown["urlscan"] += points

        evidence.append(
            f"+{points} URLScan: browser analysis classified "
            "the page as malicious."
        )

        positive_findings.append(
            "URLScan dynamic analysis produced a malicious verdict."
        )

    brand = urlscan_data.get("brand")
    page_domain = str(urlscan_data.get("page_domain") or "").lower()

    if brand:
        brand_text = str(brand).strip()
        normalized_brand = brand_text.lower().replace(" ", "")

        # Only score brand impersonation when the brand does not appear
        # to match the investigated domain.
        if normalized_brand and normalized_brand not in page_domain.replace(".", ""):
            points = 5
            risk_score += points
            score_breakdown["urlscan"] += points

            evidence.append(
                f"+{points} URLScan: possible brand impersonation "
                f"detected ."
            )

            positive_findings.append(
                f"Possible brand impersonation: {brand_text}."
            )
        else:
            informational_findings.append(
                f"URLScan identified the visible brand as {brand_text}."
            )

    redirects = urlscan_data.get("redirects", [])
    redirect_count = len(redirects) if isinstance(redirects, list) else 0

    if redirect_count >= 4:
        points = 3
        risk_score += points
        score_breakdown["urlscan"] += points

        evidence.append(
            f"+{points} URLScan: {redirect_count} redirects were observed."
        )

    domain_age_from_urlscan = urlscan_data.get("domain_age_days")

    if domain_age_from_urlscan is not None:
        domain_age_from_urlscan = _safe_int(
            domain_age_from_urlscan,
            default=-1,
        )

        if 0 <= domain_age_from_urlscan <= 30:
            points = 5
            risk_score += points
            score_breakdown["urlscan"] += points

            evidence.append(
                f"+{points} URLScan: domain age is approximately "
                f"{domain_age_from_urlscan} days."
            )

    # ========================================================
    # AbuseIPDB — maximum 20 points
    # ========================================================

    abuse_score = _safe_int(abuse_data.get("abuse_confidence"))
    total_reports = _safe_int(abuse_data.get("total_reports"))

    if abuse_score >= 75:
        points = 18
    elif abuse_score >= 50:
        points = 13
    elif abuse_score >= 25:
        points = 8
    elif abuse_score > 0:
        points = 3
    else:
        points = 0

    if points:
        risk_score += points
        score_breakdown["abuseipdb"] += points

        evidence.append(
            f"+{points} AbuseIPDB: IP abuse-confidence score is "
            f"{abuse_score}% with {total_reports} reports."
        )

        positive_findings.append(
            f"AbuseIPDB reported an abuse-confidence score of "
            f"{abuse_score}%."
        )

    if abuse_data.get("is_tor") is True:
        points = 2
        risk_score += points
        score_breakdown["abuseipdb"] += points

        evidence.append(
            f"+{points} AbuseIPDB: IP is associated with a TOR exit node."
        )

        positive_findings.append(
            "The investigated IP is associated with a TOR exit node."
        )

    usage_type = str(abuse_data.get("usage_type") or "").lower()

    if any(term in usage_type for term in ["content delivery", "cdn"]):
        informational_findings.append(
            "The checked IP belongs to a CDN or reverse-proxy provider; "
            "a low IP-reputation score may not represent the hidden origin server."
        )
    elif provider_status["abuseipdb"] and abuse_score == 0:
        informational_findings.append(
            "AbuseIPDB reported no recent abuse confidence for the checked IP."
        )

    # ========================================================
    # WHOIS — maximum 20 points
    # ========================================================

    domain_age_days = _calculate_domain_age_days(
        whois_data.get("creation_date")
    )

    if domain_age_days is not None:
        if domain_age_days <= 7:
            points = 20
        elif domain_age_days <= 30:
            points = 15
        elif domain_age_days <= 90:
            points = 10
        elif domain_age_days <= 180:
            points = 5
        else:
            points = 0

        if points:
            risk_score += points
            score_breakdown["whois"] += points

            evidence.append(
                f"+{points} WHOIS: domain is approximately "
                f"{domain_age_days} days old."
            )

            positive_findings.append(
                f"The domain was registered approximately "
                f"{domain_age_days} days ago."
            )
        else:
            informational_findings.append(
                f"WHOIS domain age is approximately "
                f"{domain_age_days} days."
            )
    else:
        informational_findings.append(
            "WHOIS domain creation date was unavailable or could not be parsed."
        )

    registrar = whois_data.get("registrar")
    dnssec = str(whois_data.get("dnssec") or "").strip().lower()

    if registrar:
        informational_findings.append(
            f"WHOIS registrar: {registrar}."
        )

    if dnssec in {"unsigned", "false", "no", "none"}:
        informational_findings.append(
            "WHOIS indicates that DNSSEC is not enabled."
        )

    # ========================================================
    # Final score, verdict and recommendation
    # ========================================================

    # The individual provider weights can exceed 100.
    # The public risk score must remain on a 0–100 scale.
    risk_score = min(risk_score, 100)

    if risk_score >= 80:
        verdict = "Critical Risk"
        recommendation = (
            "Block the URL immediately, isolate affected systems, "
            "reset exposed credentials, and begin incident-response procedures."
        )
    elif risk_score >= 60:
        verdict = "High Risk"
        recommendation = (
            "Block or quarantine the URL and perform immediate analyst review."
        )
    elif risk_score >= 35:
        verdict = "Suspicious"
        recommendation = (
            "Do not trust the URL until it has been manually reviewed."
        )
    elif risk_score >= 15:
        verdict = "Low Risk"
        recommendation = (
            "Use caution and continue monitoring for new threat intelligence."
        )
    else:
        verdict = "No Strong Threat Evidence"
        recommendation = (
            "No strong evidence was found, but this does not guarantee "
            "that the URL is safe."
        )

    # ========================================================
    # Confidence calculation
    # ========================================================

    available_providers = sum(provider_status.values())

    supporting_providers = 0

    if score_breakdown["virustotal"] > 0:
        supporting_providers += 1

    if score_breakdown["urlscan"] > 0:
        supporting_providers += 1

    if score_breakdown["abuseipdb"] > 0:
        supporting_providers += 1

    if score_breakdown["whois"] > 0:
        supporting_providers += 1

    if score_breakdown["google_safe_browsing"] > 0:
        supporting_providers += 1

    if available_providers == 0:
        confidence = 0
    else:
        coverage_score = (available_providers / 5) * 40
        agreement_score = (
            supporting_providers / available_providers
        ) * 50
        strength_score = min(risk_score, 100) * 0.10

        confidence = round(
            coverage_score + agreement_score + strength_score
        )

        confidence = max(0, min(confidence, 100))

    if not evidence:
        evidence.append(
            "No provider contributed a positive risk-scoring indicator."
        )

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "confidence": confidence,
        "recommendation": recommendation,
        "evidence": evidence,
        "positive_findings": positive_findings,
        "informational_findings": informational_findings,
        "provider_status": provider_status,
        "score_breakdown": score_breakdown,
        "domain_age_days": domain_age_days,
    }

