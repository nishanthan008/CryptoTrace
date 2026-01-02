"""
Analyzer - Correlates findings and assesses risk
"""

from ..utils.redaction import Redactor

class Analyzer:
    """
    Correlates findings and assigns risk
    """
    
    def __init__(self, redactor=None):
        self.redactor = redactor or Redactor()
        
    def process_findings(self, raw_findings):
        """
        Deduplicate, clean, and analyze findings
        """
        processed = []
        seen = set()
        
        for finding in raw_findings:
            # Create a unique hash for deduplication
            # Using location + description + evidence snippet
            unique_key = f"{finding.get('description')}:{finding['location'].get('url')}:{finding['location'].get('line', '')}"
            
            if unique_key in seen:
                continue
            seen.add(unique_key)
            
            # Enrich finding
            if finding['severity'] == 'CRITICAL':
                finding['risk_score'] = 10
            elif finding['severity'] == 'HIGH':
                finding['risk_score'] = 8
            elif finding['severity'] == 'MEDIUM':
                finding['risk_score'] = 5
            else:
                finding['risk_score'] = 1
                
            # Add OWASP mapping if missing (defaults in patterns)
            if 'owasp' not in finding:
                 finding['owasp'] = "A02:2021 – Cryptographic Failures"

            # Redact sensitive data
            safe_finding = self.redactor.redact_finding(finding)
            processed.append(safe_finding)
            
        return sorted(processed, key=lambda x: x['risk_score'], reverse=True)

    def generate_summary(self, findings):
        """
        Generate summary statistics
        """
        summary = {
            "total_findings": len(findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for f in findings:
            sev = f['severity'].lower()
            if sev in summary:
                summary[sev] += 1
            elif sev == 'informational':
                 summary['info'] += 1
                 
        return summary
