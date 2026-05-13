def calculate_cvss_score(
    response_code,
    error_message_present,
    data_exposure_detected,
    auth_state,
    attack_type
):
    score = 0.0
    attack_type = str(attack_type).strip()

    if attack_type in {"SQL Injection", "Broken Authentication", "BOLA", "Path Traversal"}:
        score += 4.0
    elif attack_type in {
        "XSS",
        "Rate Limit Abuse",
        "Excessive Data Exposure",
        "Information Disclosure",
        "Security Misconfiguration"
    }:
        score += 2.5
    else:
        score += 1.5

    if int(auth_state) == 2:
        score += 1.0
    elif int(auth_state) == 3:
        score += 2.0

    if int(error_message_present) == 1:
        score += 1.0

    if int(data_exposure_detected) == 1:
        score += 1.5

    if int(response_code) >= 500:
        score += 1.0

    return round(min(score, 10.0), 1)


def score_to_severity(score):
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"