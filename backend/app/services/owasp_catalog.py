OWASP_API_2023_CATALOG = {

    "API1:2023 - Broken Object Level Authorization": {
        "recommendations": [
            "It is recommended to enforce strict access control policies across all API endpoints.",
            "Consider implementing centralized authorization mechanisms.",
            "Use a Web Application Firewall (WAF) to monitor unauthorized access attempts."
        ],
        "mitigations": [
            "Validate user ownership before returning or modifying any object",
            "Implement role-based access control (RBAC)",
            "Avoid exposing direct object IDs in API responses"
        ],
    },

    "API2:2023 - Broken Authentication": {
        "recommendations": [
            "It is recommended to strengthen authentication mechanisms using modern standards.",
            "Consider enforcing multi-factor authentication (MFA) across all user accounts.",
            "Implement anomaly detection for suspicious login attempts."
        ],
        "mitigations": [
            "Enable MFA for all user logins",
            "Implement account lockout after multiple failed attempts",
            "Use secure password hashing (bcrypt/argon2) and enforce strong password policies"
        ],
    },

    "API3:2023 - Broken Object Property Level Authorization": {
        "recommendations": [
            "It is recommended to enforce field-level access controls.",
            "Consider minimizing data exposure based on user roles.",
            "Apply least privilege principle to API responses."
        ],
        "mitigations": [
            "Filter response fields based on user role",
            "Avoid exposing sensitive attributes in API responses",
            "Validate access to each object property individually"
        ],
    },

    "API4:2023 - Unrestricted Resource Consumption": {
        "recommendations": [
            "It is recommended to implement request throttling mechanisms.",
            "Consider monitoring API usage patterns to detect abuse.",
            "Use API gateways for traffic control and monitoring."
        ],
        "mitigations": [
            "Limit requests per IP (e.g., 100 requests/minute)",
            "Implement rate limiting using middleware (Flask-Limiter)",
            "Block or throttle repeated abusive requests"
        ],
    },

    "API5:2023 - Broken Function Level Authorization": {
        "recommendations": [
            "It is recommended to enforce strict role-based permissions on API functions.",
            "Consider separating user and admin functionality clearly.",
            "Implement access logging for sensitive operations."
        ],
        "mitigations": [
            "Restrict admin endpoints to authorized roles only",
            "Validate user roles before executing sensitive functions",
            "Implement permission checks in backend logic"
        ],
    },

    "API6:2023 - Unrestricted Access to Sensitive Business Flows": {
        "recommendations": [
            "It is recommended to monitor critical workflows for abuse patterns.",
            "Consider implementing behavioral analytics for anomaly detection.",
            "Use CAPTCHA or verification mechanisms for sensitive flows."
        ],
        "mitigations": [
            "Add rate limiting to critical business endpoints",
            "Implement CAPTCHA for repeated requests",
            "Restrict automation on sensitive operations"
        ],
    },

    "API7:2023 - Server Side Request Forgery": {
        "recommendations": [
            "It is recommended to restrict outbound API requests.",
            "Consider using allowlists for external connections.",
            "Monitor outbound traffic for unusual patterns."
        ],
        "mitigations": [
            "Block requests to internal/private IP ranges",
            "Validate all user-supplied URLs",
            "Use allowlist for external API calls"
        ],
    },

    "API8:2023 - Security Misconfiguration": {
        "recommendations": [
            "It is recommended to regularly audit API configurations.",
            "Consider implementing automated configuration scanning tools.",
            "Use secure deployment pipelines with environment isolation."
        ],
        "mitigations": [
            "Disable debug mode in production",
            "Remove unused endpoints and services",
            "Configure secure HTTP headers (CORS, CSP)"
        ],
    },

    "API9:2023 - Improper Inventory Management": {
        "recommendations": [
            "It is recommended to maintain an up-to-date API inventory.",
            "Consider implementing API discovery tools.",
            "Ensure proper documentation and version control."
        ],
        "mitigations": [
            "Track all API endpoints and versions",
            "Remove deprecated APIs",
            "Restrict access to undocumented endpoints"
        ],
    },

    "API10:2023 - Unsafe Consumption of APIs": {
        "recommendations": [
            "It is recommended to validate third-party API responses.",
            "Consider implementing schema validation for external data.",
            "Use monitoring tools to detect malicious third-party behavior."
        ],
        "mitigations": [
            "Validate and sanitize all external API data",
            "Use strict JSON schema validation",
            "Handle API errors securely"
        ],
    },
}

VULN_TO_OWASP = {
    "Broken Authentication": "API2:2023 - Broken Authentication",
    "SQL Injection": "API8:2023 - Security Misconfiguration",
    "Excessive Data Exposure": "API3:2023 - Broken Object Property Level Authorization",
    "Rate Limit Missing": "API4:2023 - Unrestricted Resource Consumption",
    "SSRF": "API7:2023 - Server Side Request Forgery",
    "Security Misconfiguration": "API8:2023 - Security Misconfiguration",
    "BOLA": "API1:2023 - Broken Object Level Authorization",
    "Object Property Exposure": "API3:2023 - Broken Object Property Level Authorization",
    "Function Level Auth": "API5:2023 - Broken Function Level Authorization",
    "Business Flow Abuse": "API6:2023 - Unrestricted Access to Sensitive Business Flows",
    "Inventory Exposure": "API9:2023 - Improper Inventory Management",
    "Unsafe API Consumption": "API10:2023 - Unsafe Consumption of APIs",
}

def get_owasp_category(vuln_name):
    return VULN_TO_OWASP.get(vuln_name, "API8:2023 - Security Misconfiguration")


def get_recommendation(category):
    item = OWASP_API_2023_CATALOG.get(category)
    if not item:
        return "It is recommended to review API security configurations."
    return item["recommendations"][0]


def get_recommendations(category):
    item = OWASP_API_2023_CATALOG.get(category)
    if not item:
        return ["It is recommended to review API security configurations."]
    return item["recommendations"]


def get_mitigation_steps(category):
    item = OWASP_API_2023_CATALOG.get(category)
    if not item:
        return ["Review API security configuration."]
    return item["mitigations"]   
