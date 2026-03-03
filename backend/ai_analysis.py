"""
AI Analysis Layer
Sends raw scan findings to Groq for enrichment, severity scoring,
remediation advice, and executive summary generation.
"""

import json
import os
from groq import Groq


SYSTEM_PROMPT = """You are a senior penetration tester and security engineer with 15+ years of experience.
You will receive raw findings from an automated security scan and must produce a structured, professional
security report in JSON format.

Your job is to:
1. Deduplicate and consolidate similar findings
2. Enrich each finding with real-world context and impact
3. Write clear, actionable remediation steps (specific, not generic)
4. Assign an overall risk score (0-100) based on the severity distribution
5. Write a 1-sentence executive summary

CRITICAL: Respond ONLY with valid JSON. No preamble, no markdown, no explanation outside JSON.

JSON structure:
{
  "risk_score": <integer 0-100>,
  "executive_summary_short": "<one sentence>",
  "executive_summary": "<2-3 paragraph detailed summary>",
  "findings": [
    {
      "name": "<finding title>",
      "severity": "<critical|high|medium|low|info>",
      "description": "<clear, non-technical explanation of what the vulnerability is>",
      "evidence": "<technical evidence from scan>",
      "impact": "<what an attacker could actually do with this>",
      "remediation": "<specific actionable steps to fix this>"
    }
  ]
}

Severity guidelines:
- critical: RCE, data breach, auth bypass, exposed credentials
- high: XSS, CSRF, SSRF, significant data exposure
- medium: Info disclosure, weak crypto, missing important headers
- low: Minor misconfigurations, defense-in-depth improvements
- info: Observations, neutral findings"""


def analyze_with_groq(url: str, raw_findings: dict, groq_api_key: str) -> dict:
    client = Groq(api_key=groq_api_key)

    all_findings = []
    for module, data in raw_findings.items():
        if isinstance(data, dict) and "findings" in data:
            all_findings.extend(data.get("findings", []))

    if not all_findings:
        return {
            "risk_score": 5,
            "executive_summary_short": "No significant vulnerabilities were automatically detected.",
            "executive_summary": (
                f"An automated scan of {url} completed without identifying high-confidence vulnerabilities. "
                "This does not guarantee the application is secure — manual testing, code review, and business "
                "logic testing are recommended to supplement automated scanning."
            ),
            "findings": [
                {
                    "name": "No Automated Findings",
                    "severity": "info",
                    "description": "The automated scanner did not identify any definitive vulnerabilities.",
                    "evidence": "",
                    "impact": "None identified by this scan.",
                    "remediation": "Consider manual penetration testing for deeper coverage.",
                }
            ],
        }

    prompt = f"""Analyze the following security scan results for: {url}

Raw Findings ({len(all_findings)} total):
{json.dumps(all_findings, indent=2)}

Produce the full security report JSON as specified."""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        temperature=0.3,
    )

    raw_text = response.choices[0].message.content.strip()

    # Strip any accidental markdown fences
    if raw_text.startswith("```"):
        raw_text = raw_text.split("\n", 1)[1]
        raw_text = raw_text.rsplit("```", 1)[0]

    try:
        report = json.loads(raw_text)
    except json.JSONDecodeError:
        report = {
            "risk_score": 50,
            "executive_summary_short": "Scan complete. Manual review of findings recommended.",
            "executive_summary": "The automated scan completed. AI analysis encountered a formatting error — raw findings are included below.",
            "findings": [
                {
                    "name": f["name"],
                    "severity": f.get("severity", "medium"),
                    "description": f.get("detail", ""),
                    "evidence": f.get("evidence", ""),
                    "impact": "See description.",
                    "remediation": "Manual review required.",
                }
                for f in all_findings
            ],
        }

    return report