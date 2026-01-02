"""
Crypto Detection Engine
"""

from ..patterns.crypto_patterns import ALL_PATTERNS
from ..patterns.libraries import detect_crypto_libraries, is_weak_algorithm
import re

class Detector:
    """
    Analyzes collected data for cryptographic materials and patterns
    """
    
    def __init__(self):
        pass

    def scan_content(self, content, location_info):
        """
        Scan a single string of content for all patterns
        
        Args:
            content (str): The content to scan (e.g., JS file source)
            location_info (dict): Metadata about origin (e.g., url, type)
            
        Returns:
            list: List of finding dicts
        """
        findings = []
        
        # 1. Regex Pattern Matching
        for category, patterns in ALL_PATTERNS.items():
            for name, info in patterns.items():
                regex = re.compile(info['pattern'], re.IGNORECASE | re.MULTILINE)
                for match in regex.finditer(content):
                    # Basic line number estimation
                    start_pos = match.start()
                    line_no = content.count('\n', 0, start_pos) + 1
                    
                    finding = {
                        "category": category,
                        "pattern_name": name,
                        "severity": info['severity'],
                        "description": info['description'],
                        "cwe": info['cwe'],
                        "evidence": match.group(0),
                        "location": {
                            "url": location_info.get('url'),
                            "line": line_no,
                            "type": location_info.get('type')
                        }
                    }
                    findings.append(finding)

        # 2. Library Detection
        libs = detect_crypto_libraries(content)
        if libs:
            # Add a finding for detected libraries
            finding = {
                "category": "library_detection",
                "pattern_name": "crypto_library",
                "severity": "INFO",
                "description": f"Detected cryptographic libraries: {', '.join(libs)}",
                "cwe": "CWE-327",
                "evidence": f"Libraries: {libs}",
                "location": {
                    "url": location_info.get('url'),
                    "type": location_info.get('type')
                }
            }
            findings.append(finding)

        return findings

    def analyze_runtime_observations(self, observations):
        """
        Analyze runtime observations from the RuntimeController
        """
        findings = []
        
        for obs in observations:
            obs_type = obs.get('type')
            details = obs.get('details', {})
            
            # 1. Web Crypto API: Encrypt/Decrypt/Generate/Import
            if obs_type in ['webcrypto_encrypt', 'webcrypto_decrypt', 'webcrypto_importKey', 'webcrypto_generateKey']:
                # Key Capture
                captured_key = details.get('key_data') or details.get('captured_key') or details.get('generated_key')
                if captured_key:
                    findings.append({
                        "category": "runtime_key_capture",
                        "severity": "CRITICAL",
                        "description": "Captured Cryptographic Key in clear text during runtime",
                        "evidence": f"Key: {captured_key}",
                        "cwe": "CWE-312",
                        "location": {"type": "runtime", "stack": obs.get("stack")}
                    })

                # IV Capture
                iv_hex = details.get('iv_hex')
                if iv_hex:
                     findings.append({
                        "category": "runtime_iv_capture",
                        "severity": "INFO",
                        "description": "Captured Initialization Vector (IV)",
                        "evidence": f"IV: {iv_hex}",
                        "location": {"type": "runtime", "stack": obs.get("stack")}
                    })
                
                # Weak Algorithm Analysis
                algo = details.get('algorithm', {})
                algo_name = algo.get('name') if isinstance(algo, dict) else algo
                is_weak, reason = is_weak_algorithm(str(algo_name))
                if is_weak:
                    findings.append({
                        "category": "weak_algorithm",
                        "severity": "HIGH",
                        "description": f"Weak crypto algorithm usage detected at runtime: {algo_name}",
                        "details": reason,
                        "location": {"type": "runtime", "stack": obs.get("stack")}
                    })

            # 2. CryptoJS Analysis
            if obs_type == 'cryptojs_aes_encrypt':
                # Key Capture
                key_hex = details.get('key_hex')
                if key_hex:
                    findings.append({
                        "category": "runtime_key_capture",
                        "severity": "CRITICAL",
                        "description": "Captured CryptoJS Key in clear text",
                        "evidence": f"Key: {key_hex}",
                        "cwe": "CWE-312",
                        "location": {"type": "runtime", "stack": obs.get("stack")}
                    })

                # IV Capture
                iv_hex = details.get('iv_hex')
                if iv_hex:
                    findings.append({
                        "category": "runtime_iv_capture",
                        "severity": "INFO",
                        "description": "Captured CryptoJS IV",
                        "evidence": f"IV: {iv_hex}",
                        "location": {"type": "runtime", "stack": obs.get("stack")}
                    })

                # Check mode
                mode = details.get('mode', '')
                if 'ECB' in mode:
                     findings.append({
                        "category": "weak_algorithm",
                        "severity": "HIGH",
                        "description": "AES encryption using ECB mode detected (insecure)",
                        "location": {"type": "runtime", "stack": obs.get("stack")}
                    })

        return findings

    def scan_storage(self, storage_data):
        """
        Scan storage for keys or secrets using patterns
        """
        findings = []
        for storage_type, data in storage_data.items():
            for k, v in data.items():
                # Scan keys and values
                combined = f"{k} = '{v}'"
                
                # specific check for JWTs in storage
                # Reuse scan_content but context is storage
                sub_findings = self.scan_content(combined, {"url": "Browser Storage", "type": storage_type})
                
                for f in sub_findings:
                    f['location']['key_name'] = k
                    findings.append(f)
                    
        return findings
