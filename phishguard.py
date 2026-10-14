#!/usr/bin/env python3
"""
PhishGuard - a local, rules-based URL indicator analyzer.
This tool analyzes the URL string only. It does not visit the website
and cannot prove that a URL is safe or malicious.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit


SUSPICIOUS_WORDS = {
    "login", "verify", "password", "account", "signin",
    "secure", "update", "banking", "wallet", "confirm",
}


def analyze_url(raw_url: str) -> dict:
    """Return a simple heuristic report for a URL string."""
    raw_url = raw_url.strip()
    findings: list[dict] = []

    if not raw_url:
        return {
            "url": raw_url,
            "risk_score": 0,
            "risk_level": "Unknown",
            "valid_url": False,
            "findings": [{"severity": "info", "message": "Please enter a URL."}],
            "disclaimer": "Heuristic indicators only; this is not a verdict."
        }

    candidate = raw_url if "://" in raw_url else "https://" + raw_url

    try:
        parts = urlsplit(candidate)
        hostname = parts.hostname
        # Accessing .port can raise ValueError for malformed ports.
        _ = parts.port
        valid = parts.scheme in {"http", "https"} and bool(hostname) and " " not in candidate
    except ValueError:
        parts = None
        hostname = None
        valid = False

    if not valid or parts is None or hostname is None:
        return {
            "url": raw_url,
            "risk_score": 0,
            "risk_level": "Invalid URL",
            "valid_url": False,
            "findings": [{"severity": "info", "message": "URL format is invalid or unsupported."}],
            "disclaimer": "Heuristic indicators only; this is not a verdict."
        }

    score = 0

    def add(points: int, severity: str, message: str) -> None:
        nonlocal score
        score += points
        findings.append({
            "severity": severity,
            "points": points,
            "message": message,
        })

    if parts.scheme == "http":
        add(15, "medium", "Uses HTTP rather than HTTPS; traffic is not encrypted by TLS.")

    try:
        ipaddress.ip_address(hostname)
        add(20, "medium", "Uses an IP address directly instead of a domain name.")
    except ValueError:
        pass

    if "@" in parts.netloc:
        add(25, "high", "Contains '@' in the authority section, which can disguise the actual host.")

    if len(raw_url) > 100:
        add(10, "low", "URL is unusually long (over 100 characters).")

    if hostname.count("-") >= 3:
        add(10, "low", "Hostname contains several hyphens.")

    if hostname.count(".") >= 4:
        add(10, "low", "Hostname contains many subdomain levels.")

    searchable = (hostname + " " + parts.path + " " + parts.query).lower()
    matched_words = sorted(word for word in SUSPICIOUS_WORDS if word in searchable)
    if matched_words:
        add(10, "low", "Contains potentially sensitive words: " + ", ".join(matched_words) + ".")

    score = min(score, 100)
    if score >= 50:
        level = "High"
    elif score >= 25:
        level = "Medium"
    elif score > 0:
        level = "Low"
    else:
        level = "No obvious indicators"

    if not findings:
        findings.append({
            "severity": "info",
            "points": 0,
            "message": "No configured indicators were found. This does not prove the URL is safe."
        })

    return {
        "url": raw_url,
        "normalized_url": candidate,
        "valid_url": True,
        "risk_score": score,
        "risk_level": level,
        "findings": findings,
        "analyzed_at_utc": datetime.now(timezone.utc).isoformat(),
        "disclaimer": (
            "This is a simple heuristic analyzer, not an AI model or reputation service. "
            "A low score does not mean a URL is safe, and a high score does not prove phishing."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PhishGuard: analyze URL strings for common suspicious indicators."
    )
    parser.add_argument("url", nargs="?", help="URL to analyze")
    parser.add_argument("--json", dest="json_path", help="Save the report as JSON")
    args = parser.parse_args()

    url = args.url or input("Enter a URL to analyze: ").strip()
    report = analyze_url(url)

    print("\n=== PhishGuard URL Analysis ===")
    print(f"URL:        {report['url']}")
    print(f"Valid URL:  {report['valid_url']}")
    print(f"Risk score: {report['risk_score']}/100")
    print(f"Risk level: {report['risk_level']}")
    print("\nFindings:")
    for item in report["findings"]:
        print(f"- [{item['severity'].upper()}] {item['message']}")
    print(f"\nNote: {report['disclaimer']}")

    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=2, ensure_ascii=False)
        print(f"\nJSON report saved to: {args.json_path}")

    return 0 if report["valid_url"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
