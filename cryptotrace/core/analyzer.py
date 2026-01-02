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
        
    def process_findings(self, raw_findings, min_confidence=5):
        """
        Deduplicate, clean, and filter findings by confidence
        """
        processed = []
        seen = set()
        
        for finding in raw_findings:
            # 1. Confidence Filtering
            conf = finding.get('confidence', 5) # Default 5 if not specified
            if isinstance(conf, str):
                conf = 10 if conf == 'High' else 5
            
            if conf < min_confidence:
                continue

            # 2. Unique Hash for Deduplication
            unique_key = f"{finding.get('description')}:{finding['location'].get('url')}:{finding['location'].get('line', '')}"
            
            if unique_key in seen:
                continue
            seen.add(unique_key)
            
            # 3. Risk Scoring (Multiplied by Confidence/10)
            base_score = 0
            if finding['severity'] == 'CRITICAL':
                base_score = 10
            elif finding['severity'] == 'HIGH':
                base_score = 8
            elif finding['severity'] == 'MEDIUM':
                base_score = 5
            else:
                base_score = 1
            
            finding['risk_score'] = round(base_score * (conf / 10.0))
            finding['confidence'] = conf
                
            # Add OWASP mapping if missing
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
