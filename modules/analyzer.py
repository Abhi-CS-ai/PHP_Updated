import re
import requests
import json
import logging

from modules.vulnerability_patterns import VULNERABILITY_PATTERNS
from modules.llm_codegemma import analyze_with_llm  # If you're using LLM
from modules.llm_codegemma import validate_findings_with_llm

logger = logging.getLogger(__name__)

def analyze_php_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as file:
        content = file.read()
    return analyze_php_content(content)

def analyze_php_url(url):
    response = requests.get(url)
    response.raise_for_status()
    return analyze_php_content(response.text)

def analyze_php_content(content):
    logger.info("Starting analysis of PHP content")

    results = {
        "summary": {
            "total_vulnerabilities": 0,
            "high_severity": 0,
            "medium_severity": 0,
            "low_severity": 0
        },
        "vulnerabilities": []
    }

    lines = content.split('\n')

    # ✅ Regex-Based Vulnerability Detection
    for i, line_content in enumerate(lines, start=1):
        for vuln_type, vuln_info in VULNERABILITY_PATTERNS.items():
            if re.search(vuln_info["pattern"], line_content, re.IGNORECASE):
                severity = vuln_info["severity"]
                vulnerability = {
                    "type": vuln_type,
                    "severity": severity,
                    "line_number": i,
                    "code_snippet": line_content.strip(),
                    "remediation": vuln_info["remediation"]
                }
                results["vulnerabilities"].append(vulnerability)
                results["summary"]["total_vulnerabilities"] += 1
                results["summary"][f"{severity.lower()}_severity"] += 1

    # ✅ Optional: Add LLM analysis (pure analysis phase)
    llm_analysis_raw = analyze_with_llm(content)  # This returns a JSON string from LLM response
    results["llm_analysis_raw"] = llm_analysis_raw

    # ✅ LLM Validation Phase (cross-check existing vulnerabilities)
    validated_findings = validate_with_llm(content, results["vulnerabilities"])
    results["validated_findings"] = json.dumps(validated_findings)

    logger.info("Analysis complete")
    return results
