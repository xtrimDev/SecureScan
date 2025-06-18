from .output import print_info, print_error
import os

def analyze_security_headers(headers):
    security_headers = [
        {
            "name": "Content-Security-Policy",
            "present": "Content-Security-Policy" in headers,
            "risk": "high"
        },
        {
            "name": "X-XSS-Protection",
            "present": "X-XSS-Protection" in headers,
            "risk": "low"
        },
        {
            "name": "X-Frame-Options",
            "present": "X-Frame-Options" in headers,
            "risk": "low"
        },
        {
            "name": "Strict-Transport-Security",
            "present": "Strict-Transport-Security" in headers,
            "risk": "medium"
        },
        {
            "name": "X-Content-Type-Options",
            "present": "X-Content-Type-Options" in headers,
            "risk": "low"
        },
        {
            "name": "Referrer-Policy",
            "present": "Referrer-Policy" in headers,
            "risk": "low"
        }
    ]
    return security_headers