"""
Secret redaction utilities for CryptoTrace
"""

import re
from ..patterns.crypto_patterns import ALL_PATTERNS

class Redactor:
    """
    Handles redaction of sensitive information from outputs
    """
    
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.redaction_mask = "***REDACTED***"
        # Compile patterns that capture potential secrets
        self.secret_patterns = []
        self._compile_secret_patterns()

    def _compile_secret_patterns(self):
        """Compile regex patterns used specifically for finding secrets to redact"""
        # Collect capture groups from key/iv/secret patterns
        categories = ['hardcoded_keys', 'ivs', 'jwt', 'encoding']
        
        for category in categories:
            if category in ALL_PATTERNS:
                for _, info in ALL_PATTERNS[category].items():
                    # specific compilation for redaction might be needed if the original patterns are complex
                    # For simplicty, we often treat the finding extraction as the source of truth,
                    # but here we provide a method to redact raw strings.
                    pass

    def redact_evidence(self, evidence, finding_type=None):
        """
        Redact sensitive parts of the evidence string.
        
        Args:
            evidence (str): The raw evidence string (e.g., "key = '12345...'")
            finding_type (str): Optional hint about what kind of finding this is
            
        Returns:
            str: Redacted evidence string
        """
        if not self.enabled or not evidence:
            return evidence

        # Heuristic: If it looks like a key assignment, redact the value
        # Look for quoted strings > 8 chars
        quote_pattern = r'["\']([A-Za-z0-9+/=]{8,})["\']'
        
        def replace_match(match):
            val = match.group(1)
            # Don't redact simple words, check for entropy or specific patterns if possible
            # For now, we redact long strings that look like secrets
            
            # Show first 2 and last 2 chars for context if length > 12
            if len(val) > 12:
                masked = f"{val[:2]}...{self.redaction_mask}...{val[-2:]}"
                return match.group(0).replace(val, masked)
            else:
                return match.group(0).replace(val, self.redaction_mask)

        redacted = re.sub(quote_pattern, replace_match, evidence)
        return redacted

    def redact_finding(self, finding):
        """
        Redact sensitive fields in a finding dictionary
        
        Args:
            finding (dict): The finding object
            
        Returns:
            dict: The finding with sensitive fields redacted
        """
        if not self.enabled:
            return finding
            
        # Create a copy to avoid modifying original
        clean_finding = finding.copy()
        
        if 'evidence' in clean_finding:
            clean_finding['evidence'] = self.redact_evidence(clean_finding['evidence'])
            
        # specific fields that might hold keys
        sensitive_fields = ['key', 'iv', 'secret', 'token', 'value']
        for field in sensitive_fields:
            if field in clean_finding:
                 clean_finding[field] = self.redaction_mask
                 
        return clean_finding

    def redact_report(self, report_data):
        """
        Redact an entire report structure
        """
        if not self.enabled:
            return report_data
            
        if isinstance(report_data, dict):
            new_data = {}
            for k, v in report_data.items():
                if k == 'findings' and isinstance(v, list):
                    new_data[k] = [self.redact_finding(f) for f in v]
                else:
                    new_data[k] = self.redact_report(v)
            return new_data
        elif isinstance(report_data, list):
            return [self.redact_report(item) for item in report_data]
        else:
            return report_data
