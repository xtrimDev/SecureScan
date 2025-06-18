from .output import print_info, print_error
import os

# List of important security headers with their associated risk levels
security_headers = {
    "Content-Security-Policy": "high",
    "Strict-Transport-Security": "medium",
    "X-Content-Type-Options": "medium",
    "X-Frame-Options": "low",
    "X-XSS-Protection": "low",
    "Referrer-Policy": "low",
    "Permissions-Policy": "low",
    "Expect-CT": "low",
    "Cache-Control": "medium",
    "Access-Control-Allow-Origin": "high",
    "Access-Control-Allow-Methods": "medium",
    "Access-Control-Allow-Headers": "medium",
    "Access-Control-Allow-Credentials": "high",
    "Cross-Origin-Resource-Policy": "high",
    "Cross-Origin-Embedder-Policy": "medium",
    "Cross-Origin-Opener-Policy": "medium"
}

def analyze_security_headers(headers: dict) -> dict:
    result = {}
    for header, risk in security_headers.items():
        status = "Present" if header in headers else "Missing"
        result[header] = {"Status": status, "Risk": risk}
    return result

def print_security_report(analysis: dict):
    for header, info in analysis.items():
        status = info["Status"]
        risk = info["Risk"]

        if status == "Present":
            print_info(f"{header}: Present (Risk: {risk})")
        else:
            print_error(f"{header}: Missing (Risk: {risk})")