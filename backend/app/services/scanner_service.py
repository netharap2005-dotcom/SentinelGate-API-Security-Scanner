import requests
from datetime import datetime
from urllib.parse import urljoin

from app.services.ml.scan_analyzer import analyze_scan
from app.services.owasp_catalog import get_owasp_category, get_recommendation


COMMON_ENDPOINTS = [
    "",
    "/users",
    "/posts",
    "/products",
    "/auth/login",
    "/login",
    "/search",
    "/debug",
    "/admin",
    "/api/users",
    "/api/v1/users",
]


def normalize_base_url(url):
    return url.rstrip("/")


def make_url(base_url, path):
    return urljoin(base_url + "/", path.lstrip("/"))


def safe_get(url, timeout=5):
    try:
        return requests.get(
            url,
            timeout=timeout,
            headers={
                "User-Agent": "SentinelGate-Scanner/1.0",
                "Accept": "application/json, */*"
            },
            allow_redirects=True
        )
    except Exception:
        return None


def safe_post(url, json_body, timeout=5):
    try:
        return requests.post(
            url,
            json=json_body,
            timeout=timeout,
            headers={
                "User-Agent": "SentinelGate-Scanner/1.0",
                "Accept": "application/json, */*",
                "Content-Type": "application/json"
            },
            allow_redirects=True
        )
    except Exception:
        return None


def discover_endpoints(base_url, scan_depth):
    if scan_depth == "shallow":
        paths = ["", "/users", "/auth/login", "/search"]
    elif scan_depth == "standard":
        paths = COMMON_ENDPOINTS[:8]
    else:
        paths = COMMON_ENDPOINTS

    live = []

    for path in paths:
        url = make_url(base_url, path)
        response = safe_get(url, timeout=4)

        if response and response.status_code in [200, 201, 202, 204, 301, 302, 401, 403, 405]:
            live.append({
                "path": path if path else "/",
                "url": url,
                "status_code": response.status_code,
                "headers": response.headers,
                "body": response.text or "",
                "content_type": response.headers.get("Content-Type", "")
            })

    return live


def build_finding(
    vuln_name,
    endpoint,
    method,
    affected_parameter,
    payload_example,
    evidence,
    response,
    error_message_present=0,
    data_exposure_detected=0,
    auth_state=1,
    status="Open"
):
    response_code = response.status_code if response else 0
    response_size = len(response.text or "") if response else 0

    finding = {
        "vuln_name": vuln_name,
        "category": "",
        "endpoint": endpoint,
        "severity": "Low",
        "status": status,
        "cvss_score": 0.0,
        "ml_severity": "Low",
        "description": evidence,
        "recommendation": "",
        "method": method,
        "affected_parameter": affected_parameter,
        "payload_example": payload_example,
        "evidence": evidence,
        "detected_at": datetime.utcnow(),
        "response_code": response_code,
        "response_size": response_size,
        "error_message_present": error_message_present,
        "data_exposure_detected": data_exposure_detected,
        "auth_state": auth_state
    }

    return enrich_with_analysis(attach_owasp_metadata(finding))


def attach_owasp_metadata(finding):
    category = get_owasp_category(finding["vuln_name"])
    finding["category"] = category
    finding["recommendation"] = get_recommendation(category)
    return finding


def enrich_with_analysis(finding):
    scan_result = {
        "response_code": finding.get("response_code", 200),
        "response_size": finding.get("response_size", 500),
        "error_message_present": finding.get("error_message_present", 0),
        "data_exposure_detected": finding.get("data_exposure_detected", 0),
        "auth_state": finding.get("auth_state", 1),
        "attack_type": finding.get("vuln_name", "Unknown")
    }

    analysis = analyze_scan(scan_result)

    finding["cvss_score"] = analysis["cvss_score"]
    finding["ml_severity"] = analysis["ml_predicted_severity"]
    finding["severity"] = analysis["final_severity"]

    return finding


def run_scan(target_url, scan_depth):
    base_url = normalize_base_url(target_url)

    live_endpoints = discover_endpoints(base_url, scan_depth)
    findings = []

    findings += test_security_headers(live_endpoints)
    findings += test_sensitive_data_exposure(live_endpoints)
    findings += test_sql_injection(base_url, live_endpoints)
    findings += test_broken_auth(base_url)
    findings += test_rate_limit(base_url, live_endpoints)

    if scan_depth in ["standard", "deep"]:
        findings += test_bola_like_access(base_url, live_endpoints)
        findings += test_cors_misconfiguration(live_endpoints)

    if scan_depth == "deep":
        findings += test_debug_exposure(base_url)
        findings += test_ssrf(base_url)

    unique = {}
    for finding in findings:
        key = (finding["vuln_name"], finding["endpoint"], finding["affected_parameter"])
        unique[key] = finding

    return list(unique.values())


def test_security_headers(live_endpoints):
    findings = []

    important_headers = {
        "Strict-Transport-Security": "HSTS header missing",
        "X-Content-Type-Options": "X-Content-Type-Options header missing",
        "Content-Security-Policy": "Content-Security-Policy header missing"
    }

    for item in live_endpoints[:3]:
        response = safe_get(item["url"])
        if not response:
            continue

        missing = [
            message for header, message in important_headers.items()
            if header not in response.headers
        ]

        if len(missing) >= 2:
            findings.append(build_finding(
                vuln_name="Security Misconfiguration",
                endpoint=item["path"],
                method="GET",
                affected_parameter="headers",
                payload_example="Security header inspection",
                evidence="; ".join(missing),
                response=response,
                error_message_present=0,
                data_exposure_detected=0,
                auth_state=1
            ))

    return findings


def test_sensitive_data_exposure(live_endpoints):
    findings = []
    sensitive_words = ["password", "token", "secret", "api_key", "apikey", "access_token", "refresh_token"]

    for item in live_endpoints:
        body = item["body"].lower()

        exposed = [word for word in sensitive_words if word in body]

        if exposed:
            findings.append(build_finding(
                vuln_name="Excessive Data Exposure",
                endpoint=item["path"],
                method="GET",
                affected_parameter=", ".join(exposed[:3]),
                payload_example="Normal API response inspection",
                evidence=f"Response contains sensitive-looking fields: {', '.join(exposed[:3])}",
                response=safe_get(item["url"]),
                error_message_present=0,
                data_exposure_detected=1,
                auth_state=2
            ))

    return findings


def test_sql_injection(base_url, live_endpoints):
    findings = []

    sql_paths = [item["path"] for item in live_endpoints if item["path"] in ["/users", "/api/users", "/api/v1/users"]]
    if not sql_paths:
        sql_paths = ["/users"]

    suspicious_indicators = [
        "sql syntax",
        "mysql",
        "postgres",
        "sqlite",
        "odbc",
        "database error",
        "syntax error",
        "unclosed quotation"
    ]

    for path in sql_paths:
        test_url = make_url(base_url, path) + "?id=1' OR '1'='1"
        response = safe_get(test_url)

        if not response:
            continue

        body = response.text.lower()

        if response.status_code >= 500 or any(word in body for word in suspicious_indicators):
            findings.append(build_finding(
                vuln_name="SQL Injection",
                endpoint=path,
                method="GET",
                affected_parameter="id",
                payload_example="' OR '1'='1",
                evidence="SQL-like payload caused database/error behavior in the response.",
                response=response,
                error_message_present=1,
                data_exposure_detected=0,
                auth_state=1
            ))

    return findings


def test_broken_auth(base_url):
    findings = []

    auth_paths = ["/auth/login", "/login", "/api/auth/login"]

    for path in auth_paths:
        test_url = make_url(base_url, path)
        response = safe_post(
            test_url,
            {"username": "admin", "password": "wrongpassword"},
            timeout=5
        )

        if not response:
            continue

        body = response.text.lower()

        success_words = ["token", "access_token", "logged", "success", "jwt"]

        if response.status_code == 200 and any(word in body for word in success_words):
            findings.append(build_finding(
                vuln_name="Broken Authentication",
                endpoint=path,
                method="POST",
                affected_parameter="password",
                payload_example="wrongpassword",
                evidence="Login endpoint returned success-like response for invalid credentials.",
                response=response,
                error_message_present=0,
                data_exposure_detected=1,
                auth_state=3,
                status="Investigating"
            ))

    return findings


def test_rate_limit(base_url, live_endpoints):
    findings = []

    candidate_paths = [item["path"] for item in live_endpoints if item["path"] in ["/search", "/users", "/posts", "/products"]]

    if not candidate_paths:
        return findings

    path = candidate_paths[0]
    test_url = make_url(base_url, path)

    success_count = 0
    rate_limited_count = 0
    last_response = None

    for _ in range(12):
        response = safe_get(test_url, timeout=2)
        last_response = response

        if not response:
            continue

        if response.status_code == 429:
            rate_limited_count += 1
        elif response.status_code in [200, 201, 202]:
            success_count += 1

    if success_count >= 10 and rate_limited_count == 0:
        findings.append(build_finding(
            vuln_name="Rate Limit Missing",
            endpoint=path,
            method="GET",
            affected_parameter="request frequency",
            payload_example="12 repeated requests",
            evidence=f"{success_count} repeated requests were accepted without HTTP 429 rate limiting.",
            response=last_response,
            error_message_present=0,
            data_exposure_detected=0,
            auth_state=1
        ))

    return findings


def test_bola_like_access(base_url, live_endpoints):
    findings = []

    user_paths = [item["path"] for item in live_endpoints if "user" in item["path"].lower()]

    for path in user_paths[:2]:
        test_url = make_url(base_url, path.rstrip("/") + "/1")
        response = safe_get(test_url)

        if not response:
            continue

        body = response.text.lower()

        if response.status_code == 200 and any(word in body for word in ["email", "username", "address", "phone"]):
            findings.append(build_finding(
                vuln_name="BOLA",
                endpoint=path.rstrip("/") + "/1",
                method="GET",
                affected_parameter="object_id",
                payload_example="Access object ID 1 without authentication",
                evidence="User-like object data was accessible directly by object ID.",
                response=response,
                error_message_present=0,
                data_exposure_detected=1,
                auth_state=2
            ))

    return findings


def test_cors_misconfiguration(live_endpoints):
    findings = []

    for item in live_endpoints[:3]:
        try:
            response = requests.get(
                item["url"],
                timeout=4,
                headers={
                    "Origin": "https://evil.example",
                    "User-Agent": "SentinelGate-Scanner/1.0"
                }
            )
        except Exception:
            continue

        allow_origin = response.headers.get("Access-Control-Allow-Origin", "")
        allow_credentials = response.headers.get("Access-Control-Allow-Credentials", "")

        if allow_origin == "*" or (
            "evil.example" in allow_origin and allow_credentials.lower() == "true"
        ):
            findings.append(build_finding(
                vuln_name="Security Misconfiguration",
                endpoint=item["path"],
                method="GET",
                affected_parameter="CORS",
                payload_example="Origin: https://evil.example",
                evidence="Potentially unsafe CORS policy detected.",
                response=response,
                error_message_present=0,
                data_exposure_detected=0,
                auth_state=1
            ))

    return findings


def test_debug_exposure(base_url):
    findings = []
    debug_paths = ["/debug", "/.env", "/config", "/server-status"]

    indicators = ["traceback", "debug", "exception", "stack trace", "secret_key", "database_url"]

    for path in debug_paths:
        response = safe_get(make_url(base_url, path))

        if not response:
            continue

        body = response.text.lower()

        if response.status_code == 200 and any(word in body for word in indicators):
            findings.append(build_finding(
                vuln_name="Security Misconfiguration",
                endpoint=path,
                method="GET",
                affected_parameter="debug/config",
                payload_example=path,
                evidence="Debug/configuration information appears to be exposed.",
                response=response,
                error_message_present=1,
                data_exposure_detected=1,
                auth_state=1
            ))

    return findings


def test_ssrf(base_url):
    findings = []
    ssrf_paths = ["/fetch", "/url", "/proxy"]

    for path in ssrf_paths:
        test_url = make_url(base_url, path) + "?url=http://169.254.169.254/latest/meta-data/"
        response = safe_get(test_url)

        if not response:
            continue

        body = response.text.lower()

        if response.status_code == 200 and any(word in body for word in ["ami-id", "instance-id", "metadata"]):
            findings.append(build_finding(
                vuln_name="SSRF",
                endpoint=path,
                method="GET",
                affected_parameter="url",
                payload_example="http://169.254.169.254/latest/meta-data/",
                evidence="Endpoint appears to fetch internal metadata URL content.",
                response=response,
                error_message_present=0,
                data_exposure_detected=1,
                auth_state=2
            ))

    return findings