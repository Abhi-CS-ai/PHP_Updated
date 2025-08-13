import re
import os
import json
import subprocess
import requests
from modules.vulnerability_patterns import VULNERABILITY_PATTERNS

# Path to Node.js php-parser bridge script
TOOLS_PATH = os.path.join(os.path.dirname(__file__), "..", "tools", "php_ast_bridge.js")


def get_safe_lines_from_node(content):
    """
    Call Node.js php-parser bridge to get line numbers with safe functions.
    """
    try:
        proc = subprocess.Popen(
            ["node", TOOLS_PATH],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = proc.communicate(content, timeout=10)

        if stderr:
            print("[Node Bridge Error]:", stderr)

        data = json.loads(stdout)
        return set(data.get("safeLines", []))
    except Exception as e:
        print("[Analyzer Error]: Error calling Node bridge:", e)
        return set()


def strip_comments(content):
    """
    Remove PHP single-line and multi-line comments.
    """
    return re.sub(r'//.*|/\*[\s\S]*?\*/', '', content)


def suggest_fix_for(vuln_type, snippet):
    """
    Provide contextual example fixes for each vulnerability type.
    """
    if vuln_type == "SQL Injection":
        return "Use prepared statements with bound parameters. Example: $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');"
    if vuln_type == "Cross-Site Scripting (XSS)":
        return f"Sanitize output. Example: echo htmlspecialchars({snippet}, ENT_QUOTES, 'UTF-8');"
    if vuln_type == "File Inclusion":
        return "Whitelist allowed files and validate paths before including."
    if vuln_type == "Command Injection":
        return "Avoid direct shell execution. Use escapeshellarg() or escapeshellcmd()."
    if vuln_type == "Insecure File Upload":
        return "Restrict file types, validate MIME, and store files outside web root."
    return "Refer to OWASP guidelines for secure coding."


def detect_compound_vulns(results):
    """
    Detect dangerous combinations of vulnerabilities and escalate severity.
    This version is keyword-based, so it's resilient to pattern name changes.
    """
    found_types = {v['type'].lower() for v in results['vulnerabilities']}

    # Helper to check if any keyword is present in found types
    def has_keyword(keyword):
        return any(keyword.lower() in t for t in found_types)

    # Detect Remote Code Execution Risk from upload + inclusion
    if has_keyword("upload") and has_keyword("inclusion"):
        results['vulnerabilities'].append({
            "type": "Remote Code Execution Risk",
            "severity": "High",
            "line_number": None,
            "code_snippet": "Combination of insecure file upload and file inclusion",
            "remediation": "Avoid allowing uploaded files to be included or executed."
        })
        results['summary']['total_vulnerabilities'] += 1
        results['summary']['high_severity'] += 1

    return results



def analyze_php_file(filepath):
    """
    Analyze a PHP file for vulnerabilities.
    """
    if not os.path.exists(filepath):
        return {"error": "File not found"}

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
        return analyze_php_content(content)
    except Exception as e:
        return {"error": str(e)}


def analyze_php_url(url):
    """
    Analyze a PHP URL for vulnerabilities.
    """
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            return {"error": f"Failed to fetch URL. Status: {response.status_code}"}

        if 'php' not in response.headers.get('Content-Type', '') and 'html' not in response.headers.get('Content-Type', ''):
            return {"error": "The URL does not appear to be a PHP or HTML page"}

        return analyze_php_content(response.text)
    except requests.exceptions.RequestException as e:
        return {"error": f"Error fetching URL: {str(e)}"}


def analyze_php_content(content):
    """
    Analyze PHP content for vulnerabilities using:
    - Regex pattern matching
    - Node.js AST parsing to skip safe lines
    - Compound vulnerability detection
    """
    results = {
        "summary": {
            "total_vulnerabilities": 0,
            "high_severity": 0,
            "medium_severity": 0,
            "low_severity": 0
        },
        "vulnerabilities": []
    }

    # 1. Get safe lines from Node.js AST parser
    safe_lines = get_safe_lines_from_node(content)

    # 2. Remove comments to avoid false positives
    content_cleaned = strip_comments(content)
    lines = content_cleaned.split('\n')

    # 3. Scan each line for vulnerabilities
    for line_number, line_content in enumerate(lines, start=1):
        for pattern_name, pattern_info in VULNERABILITY_PATTERNS.items():
            matches = re.finditer(pattern_info['pattern'], line_content)

            for _ in matches:
                # Skip if this line is already considered safe
                if line_number in safe_lines:
                    continue

                results['vulnerabilities'].append({
                    "type": pattern_name,
                    "severity": pattern_info['severity'],
                    "line_number": line_number,
                    "code_snippet": line_content.strip(),
                    "remediation": f"{pattern_info['remediation']} {suggest_fix_for(pattern_name, line_content.strip())}"
                })
                results["summary"]["total_vulnerabilities"] += 1
                results["summary"][f"{pattern_info['severity'].lower()}_severity"] += 1

    # 4. Check for compound vulnerabilities
    results = detect_compound_vulns(results)

    return results
