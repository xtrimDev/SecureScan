def analyze_security_headers(headers):
    # Make headers case-insensitive
    headers = {k.lower(): v for k, v in headers.items()}

    security_headers = [
        {
            "name": "Content-Security-Policy",
            "present": "content-security-policy" in headers,
            "risk": "high"
        },
        {
            "name": "X-XSS-Protection",
            "present": "x-xss-protection" in headers,
            "risk": "low"
        },
        {
            "name": "X-Frame-Options",
            "present": "x-frame-options" in headers,
            "risk": "low"
        },
        {
            "name": "Strict-Transport-Security",
            "present": "strict-transport-security" in headers,
            "risk": "medium"
        },
        {
            "name": "X-Content-Type-Options",
            "present": "x-content-type-options" in headers,
            "risk": "low"
        },
        {
            "name": "Referrer-Policy",
            "present": "referrer-policy" in headers,
            "risk": "low"
        }
    ]

    return security_headers
