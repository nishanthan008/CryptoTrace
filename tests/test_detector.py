import unittest
import sys
import os

# Add parent dir to path to import cryptotrace
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from cryptotrace.core.detector import Detector
from cryptotrace.core.analyzer import Analyzer
from cryptotrace.patterns.crypto_patterns import ALL_PATTERNS

class TestDetector(unittest.TestCase):
    def setUp(self):
        self.detector = Detector()
        self.analyzer = Analyzer()

    def test_hardcoded_key_detection(self):
        content = """
        const secretKey = '1234567812345678';
        var appConfig = {
            apiKey: "abcdef1234567890abcdef1234567890"
        };
        """
        findings = self.detector.scan_content(content, {"url": "test.js", "type": "script"})
        
        # Should find at least one key
        key_findings = [f for f in findings if f['category'] == 'hardcoded_keys']
        self.assertTrue(len(key_findings) > 0)
        self.assertEqual(key_findings[0]['severity'], 'CRITICAL')

    def test_weak_algo_detection_runtime(self):
        observations = [
            {
                "type": "webcrypto_encrypt",
                "details": {
                    "algorithm": "SHA-1"
                },
                "stack": "Error\n    at window.crypto.subtle.encrypt..."
            }
        ]
        
        findings = self.detector.analyze_runtime_observations(observations)
        self.assertTrue(len(findings) > 0)
        self.assertIn("Weak crypto algorithm", findings[0]['description'])

    def test_analyzer_risk_scoring(self):
        raw_findings = [
            {
                "category": "hardcoded_keys",
                "severity": "CRITICAL",
                "description": "Found key",
                "cwe": "CWE-321",
                "evidence": "key='1234567812345678'",
                "location": {"url": "test.js", "line": 1}
            }
        ]
        
        processed = self.analyzer.process_findings(raw_findings)
        self.assertEqual(processed[0]['risk_score'], 10)
        self.assertNotEqual(processed[0]['evidence'], "key='1234567812345678'") # Should be redacted
        self.assertTrue("***REDACTED***" in processed[0]['evidence'])

if __name__ == '__main__':
    unittest.main()
