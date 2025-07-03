import requests
import os
import json

# Hugging Face API setup
HF_API_URL = "https://api-inference.huggingface.co/models/google/CodeGemma-7b-it"
HF_TOKEN = os.getenv("HF_API_TOKEN")

headers = {
    "Authorization": f"Bearer {HF_TOKEN}"
}

# -------------------------
# 1. Run raw LLM analysis
# -------------------------
def analyze_with_llm(php_code: str) -> str:
    """
    Sends the PHP code to the CodeGemma model and returns raw vulnerability analysis.
    """
    prompt = f"""You are a cybersecurity assistant. Analyze the following PHP code and list any security vulnerabilities.

Respond in JSON format like:
{{
  "vulnerabilities": [
    {{
      "type": "<type>",
      "description": "<explanation>",
      "line_hint": <line number or -1>
    }}
  ]
}}

PHP code:
{php_code}
"""
    payload = {"inputs": prompt, "parameters": {"max_new_tokens": 512}}

    try:
        response = requests.post(HF_API_URL, headers=headers, json=payload, timeout=60)
        response.raise_for_status()
        result = response.json()
        if isinstance(result, list):
            return result[0]["generated_text"]
        else:
            return json.dumps(result)
    except Exception as e:
        return json.dumps({"error": str(e)})

# ----------------------------------------
# 2. LLM-based validation of merged issues
# ----------------------------------------
def validate_findings_with_llm(php_code: str, findings: list) -> str:
    """
    Submits merged findings + PHP code to the LLM and asks it to filter out false positives.
    """
    # Format the merged findings into readable JSON string
    findings_json = json.dumps(findings, indent=2)

    prompt = f"""You are a cybersecurity expert. Below is a list of findings (detected by static analysis and AI), along with the PHP code.

Your task is to determine for each finding:
- Is it a REAL vulnerability? (TRUE / FALSE)
- Give a short explanation

Respond in JSON format as:
{{
  "results": [
    {{
      "type": "<type>",
      "line_hint": <line>,
      "verdict": "TRUE" or "FALSE",
      "explanation": "<short reason>"
    }}
  ]
}}

Findings:
{findings_json}

PHP Code:
{php_code}
"""
    payload = {"inputs": prompt, "parameters": {"max_new_tokens": 512}}

    try:
        response = requests.post(HF_API_URL, headers=headers, json=payload, timeout=60)
        response.raise_for_status()
        result = response.json()
        if isinstance(result, list):
            return result[0]["generated_text"]
        else:
            return json.dumps(result)
    except Exception as e:
        return json.dumps({"error": str(e)})
