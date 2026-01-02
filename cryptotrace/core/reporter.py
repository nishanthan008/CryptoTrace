"""
Reporter - Generates reports in various formats
"""

import json
import logging
from datetime import datetime
import os

class Reporter:
    """
    Generates reports in JSON, SARIF, and Markdown
    """
    
    def __init__(self, scan_data):
        self.scan_data = scan_data
        
    def save_json(self, output_file):
        """Save report as JSON"""
        try:
            with open(output_file, 'w') as f:
                json.dump(self.scan_data, f, indent=2)
            print(f"Report saved to {output_file}")
        except Exception as e:
            print(f"Error saving JSON report: {e}")

    def save_markdown(self, output_file):
        """Save report as Markdown"""
        summary = self.scan_data.get('summary', {})
        findings = self.scan_data.get('findings', [])
        
        md = f"""# CryptoTrace Security Scan Report

**Target:** {self.scan_data.get('target')}
**Date:** {self.scan_data.get('timestamp')}
**Scan ID:** {self.scan_data.get('scan_id')}

## Executive Summary

| Total Findings | Critical | High | Medium | Low |
|:---:|:---:|:---:|:---:|:---:|
| {summary.get('total_findings', 0)} | {summary.get('critical', 0)} | {summary.get('high', 0)} | {summary.get('medium', 0)} | {summary.get('low', 0)} |

## Detailed Findings

"""
        
        if not findings:
            md += "*No findings detected.*"
        
        for idx, f in enumerate(findings, 1):
            md += f"""### {idx}. {f.get('description')}

- **Severity:** **{f.get('severity')}**
- **Category:** {f.get('category')}
- **CWE:** {f.get('cwe')}
- **Location:** `{f.get('location', {}).get('url', 'unknown')}` (Line: {f.get('location', {}).get('line', 'N/A')})

**Evidence:**
```javascript
{f.get('evidence', '')}
```

---
"""
        
        try:
            with open(output_file, 'w') as f:
                f.write(md)
            print(f"Report saved to {output_file}")
        except Exception as e:
            print(f"Error saving Markdown report: {e}")

    def save_sarif(self, output_file):
        """Save report as SARIF (Static Analysis Results Interchange Format)"""
        # Basic SARIF shell
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0-rtm.5.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "CryptoTrace",
                        "informationUri": "https://github.com/yourusername/cryptotrace",
                        "version": "1.0.0",
                        "rules": []
                    }
                },
                "results": []
            }]
        }
        
        # Populate results
        results = []
        rules = {} # To deduplicate rule definitions
        
        for f in self.scan_data.get('findings', []):
            rule_id = f.get('category').upper()
            
            # Add rule if not exists
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {"text": f.get('description')},
                    "defaultConfiguration": {"level": self._map_severity_to_sarif(f.get('severity'))}
                }
            
            # Add result
            results.append({
                "ruleId": rule_id,
                "level": self._map_severity_to_sarif(f.get('severity')),
                "message": {"text": f.get('description')},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get('location', {}).get('url', 'unknown')},
                        "region": {"startLine": int(f.get('location', {}).get('line', 1))}
                    }
                }]
            })
            
        sarif['runs'][0]['tool']['driver']['rules'] = list(rules.values())
        sarif['runs'][0]['results'] = results
        
        try:
            with open(output_file, 'w') as f:
                json.dump(sarif, f, indent=2)
            print(f"Report saved to {output_file}")
        except Exception as e:
             print(f"Error saving SARIF report: {e}")

    def _map_severity_to_sarif(self, severity):
        mapping = {
            'CRITICAL': 'error',
            'HIGH': 'error',
            'MEDIUM': 'warning',
            'LOW': 'note',
            'INFO': 'note'
        }
        return mapping.get(severity, 'warning')
