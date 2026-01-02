"""
Comprehensive cryptographic pattern database for detection
"""

import re

# Hardcoded key patterns
HARDCODED_KEY_PATTERNS = {
    'generic_key': {
        'pattern': r'(?:key|secret|password|passphrase|encryptionKey|decryptionKey|secretKey|privateKey)\s*[:=]\s*["\']([A-Za-z0-9+/=]{16,})["\']',
        'description': 'Generic hardcoded key pattern',
        'severity': 'CRITICAL',
        'cwe': 'CWE-321'
    },
    'hex_key': {
        'pattern': r'(?:key|secret)\s*[:=]\s*["\']([A-Fa-f0-9]{32,})["\']',
        'description': 'Hexadecimal encoded key',
        'severity': 'CRITICAL',
        'cwe': 'CWE-321'
    },
    'base64_key': {
        'pattern': r'(?:key|secret)\s*[:=]\s*["\']([A-Za-z0-9+/]{22,}={0,2})["\']',
        'description': 'Base64 encoded key',
        'severity': 'CRITICAL',
        'cwe': 'CWE-321'
    },
    'aes_key_assignment': {
        'pattern': r'(?:AES|aes).*?[kK]ey\s*[:=]\s*["\']([^"\']{16,})["\']',
        'description': 'AES key assignment',
        'severity': 'CRITICAL',
        'cwe': 'CWE-321'
    }
}

# Initialization Vector (IV) patterns
IV_PATTERNS = {
    'generic_iv': {
        'pattern': r'(?:iv|nonce|salt|initialization[_\s]?vector)\s*[:=]\s*["\']([A-Fa-f0-9]{16,})["\']',
        'description': 'Hardcoded initialization vector',
        'severity': 'HIGH',
        'cwe': 'CWE-329'
    },
    'static_iv': {
        'pattern': r'(?:iv|nonce)\s*[:=]\s*["\']([A-Za-z0-9+/=]{16,})["\']',
        'description': 'Static IV value',
        'severity': 'HIGH',
        'cwe': 'CWE-329'
    },
    'zero_iv': {
        'pattern': r'(?:iv|nonce)\s*[:=]\s*["\']0{16,}["\']',
        'description': 'Zero-filled IV (highly insecure)',
        'severity': 'CRITICAL',
        'cwe': 'CWE-329'
    }
}

# CryptoJS library patterns
CRYPTOJS_PATTERNS = {
    'cryptojs_aes_encrypt': {
        'pattern': r'CryptoJS\.AES\.encrypt\s*\(',
        'description': 'CryptoJS AES encryption usage',
        'severity': 'MEDIUM',
        'cwe': 'CWE-327'
    },
    'cryptojs_aes_decrypt': {
        'pattern': r'CryptoJS\.AES\.decrypt\s*\(',
        'description': 'CryptoJS AES decryption usage',
        'severity': 'MEDIUM',
        'cwe': 'CWE-327'
    },
    'cryptojs_des': {
        'pattern': r'CryptoJS\.DES\.',
        'description': 'CryptoJS DES usage (weak algorithm)',
        'severity': 'HIGH',
        'cwe': 'CWE-327'
    },
    'cryptojs_tripledes': {
        'pattern': r'CryptoJS\.TripleDES\.',
        'description': 'CryptoJS Triple DES usage',
        'severity': 'MEDIUM',
        'cwe': 'CWE-327'
    },
    'cryptojs_rc4': {
        'pattern': r'CryptoJS\.RC4\.',
        'description': 'CryptoJS RC4 usage (broken algorithm)',
        'severity': 'CRITICAL',
        'cwe': 'CWE-327'
    },
    'cryptojs_md5': {
        'pattern': r'CryptoJS\.MD5\s*\(',
        'description': 'CryptoJS MD5 usage (weak hash)',
        'severity': 'HIGH',
        'cwe': 'CWE-327'
    },
    'cryptojs_sha1': {
        'pattern': r'CryptoJS\.SHA1\s*\(',
        'description': 'CryptoJS SHA1 usage (weak hash)',
        'severity': 'HIGH',
        'cwe': 'CWE-327'
    }
}

# Web Crypto API patterns
WEBCRYPTO_PATTERNS = {
    'subtle_encrypt': {
        'pattern': r'crypto\.subtle\.encrypt\s*\(',
        'description': 'Web Crypto API encryption',
        'severity': 'MEDIUM',
        'cwe': 'CWE-327'
    },
    'subtle_decrypt': {
        'pattern': r'crypto\.subtle\.decrypt\s*\(',
        'description': 'Web Crypto API decryption',
        'severity': 'MEDIUM',
        'cwe': 'CWE-327'
    },
    'subtle_importkey': {
        'pattern': r'crypto\.subtle\.importKey\s*\(',
        'description': 'Web Crypto API key import',
        'severity': 'MEDIUM',
        'cwe': 'CWE-327'
    },
    'subtle_generatekey': {
        'pattern': r'crypto\.subtle\.generateKey\s*\(',
        'description': 'Web Crypto API key generation',
        'severity': 'LOW',
        'cwe': 'CWE-327'
    },
    'subtle_derivebits': {
        'pattern': r'crypto\.subtle\.deriveBits\s*\(',
        'description': 'Web Crypto API key derivation',
        'severity': 'MEDIUM',
        'cwe': 'CWE-327'
    },
    # Looser patterns for minified/bundled code
    'generic_encrypt': {
        'pattern': r'\.encrypt\s*\(',
        'description': 'Generic encryption method call (potential library)',
        'severity': 'LOW',
        'cwe': 'CWE-327'
    },
    'generic_decrypt': {
        'pattern': r'\.decrypt\s*\(',
        'description': 'Generic decryption method call (potential library)',
        'severity': 'LOW',
        'cwe': 'CWE-327'
    }
}

# Variable name patterns (potential secrets in code)
VARIABLE_NAME_PATTERNS = {
    'secret_var': {
        'pattern': r'(?:var|let|const)\s+[a-zA-Z0-9_$]*(?:secret|key|token|auth|pass)[a-zA-Z0-9_$]*\s*=',
        'description': 'Variable name suggesting secret storage',
        'severity': 'MEDIUM',
        'cwe': 'CWE-798'
    },
    'api_key_var': {
         'pattern': r'(?:var|let|const)\s+[a-zA-Z0-9_$]*(?:apiKey|ApiKey|API_KEY)[a-zA-Z0-9_$]*\s*=',
         'description': 'Variable name suggesting API key',
         'severity': 'MEDIUM',
         'cwe': 'CWE-798'
    }
}

# Environment variable usage in frontend code
ENV_VAR_PATTERNS = {
    'process_env': {
        'pattern': r'process\.env\.[a-zA-Z0-9_]+',
        'description': 'Accessing process.env in client-side code (potential leak)',
        'severity': 'LOW',
        'cwe': 'CWE-200'
    }
}

# Node-forge library patterns
FORGE_PATTERNS = {
    'forge_cipher': {
        'pattern': r'forge\.cipher\.',
        'description': 'Node-forge cipher usage',
        'severity': 'MEDIUM',
        'cwe': 'CWE-327'
    },
    'forge_aes': {
        'pattern': r'forge\.(?:aes|cipher)\.createCipher\s*\(',
        'description': 'Node-forge AES cipher creation',
        'severity': 'MEDIUM',
        'cwe': 'CWE-327'
    },
    'forge_des': {
        'pattern': r'forge\.des\.',
        'description': 'Node-forge DES usage (weak algorithm)',
        'severity': 'HIGH',
        'cwe': 'CWE-327'
    }
}

# Weak algorithm patterns
WEAK_ALGORITHM_PATTERNS = {
    'md5_usage': {
        'pattern': r'(?:md5|MD5)\s*\(',
        'description': 'MD5 hash usage (cryptographically broken)',
        'severity': 'HIGH',
        'cwe': 'CWE-327'
    },
    'sha1_usage': {
        'pattern': r'(?:sha1|SHA1)\s*\(',
        'description': 'SHA1 hash usage (weak)',
        'severity': 'HIGH',
        'cwe': 'CWE-327'
    },
    'des_usage': {
        'pattern': r'\bDES\b',
        'description': 'DES algorithm usage (obsolete)',
        'severity': 'HIGH',
        'cwe': 'CWE-327'
    },
    'rc4_usage': {
        'pattern': r'\bRC4\b',
        'description': 'RC4 algorithm usage (broken)',
        'severity': 'CRITICAL',
        'cwe': 'CWE-327'
    },
    'ecb_mode': {
        'pattern': r'["\']ECB["\']|mode\s*:\s*ECB',
        'description': 'ECB mode usage (insecure)',
        'severity': 'HIGH',
        'cwe': 'CWE-327'
    }
}

# Base64/Hex encoding patterns (potential secrets)
ENCODING_PATTERNS = {
    'base64_decode': {
        'pattern': r'atob\s*\(["\']([A-Za-z0-9+/]{22,}={0,2})["\']',
        'description': 'Base64 decoded value (potential secret)',
        'severity': 'MEDIUM',
        'cwe': 'CWE-798'
    },
    'base64_encode': {
        'pattern': r'btoa\s*\(["\']([^"\']{8,})["\']',
        'description': 'Base64 encoded value',
        'severity': 'LOW',
        'cwe': 'CWE-798'
    },
    'hex_string': {
        'pattern': r'["\']([A-Fa-f0-9]{40,})["\']',
        'description': 'Long hexadecimal string (potential key)',
        'severity': 'MEDIUM',
        'cwe': 'CWE-798'
    }
}

# Key derivation patterns
KDF_PATTERNS = {
    'pbkdf2_weak_iterations': {
        'pattern': r'(?:PBKDF2|pbkdf2).*?(?:iterations?|count)\s*[:=]\s*([1-9]\d{0,3})\b',
        'description': 'PBKDF2 with weak iteration count (<10000)',
        'severity': 'HIGH',
        'cwe': 'CWE-916'
    },
    'pbkdf2_usage': {
        'pattern': r'(?:PBKDF2|pbkdf2)\s*\(',
        'description': 'PBKDF2 key derivation usage',
        'severity': 'LOW',
        'cwe': 'CWE-916'
    }
}

# Client-side encryption patterns (potential false sense of security)
CLIENT_SIDE_PATTERNS = {
    'encrypt_before_send': {
        'pattern': r'(?:encrypt|cipher)\s*\([^)]*\).*?(?:fetch|ajax|xhr|axios|post)\s*\(',
        'description': 'Client-side encryption before transmission',
        'severity': 'HIGH',
        'cwe': 'CWE-311'
    },
    'decrypt_after_receive': {
        'pattern': r'(?:fetch|ajax|xhr|axios|get)\s*\([^)]*\).*?(?:decrypt|decipher)\s*\(',
        'description': 'Client-side decryption after reception',
        'severity': 'HIGH',
        'cwe': 'CWE-311'
    }
}

# JWT patterns (potential exposure)
JWT_PATTERNS = {
    'jwt_hardcoded': {
        'pattern': r'["\']eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+["\']',
        'description': 'Hardcoded JWT token',
        'severity': 'CRITICAL',
        'cwe': 'CWE-798'
    },
    'jwt_secret': {
        'pattern': r'(?:jwt|JWT).*?[sS]ecret\s*[:=]\s*["\']([^"\']{8,})["\']',
        'description': 'JWT secret key',
        'severity': 'CRITICAL',
        'cwe': 'CWE-798'
    }
}

# Combine all patterns
ALL_PATTERNS = {
    'hardcoded_keys': HARDCODED_KEY_PATTERNS,
    'ivs': IV_PATTERNS,
    'cryptojs': CRYPTOJS_PATTERNS,
    'webcrypto': WEBCRYPTO_PATTERNS,
    'forge': FORGE_PATTERNS,
    'weak_algorithms': WEAK_ALGORITHM_PATTERNS,
    'encoding': ENCODING_PATTERNS,
    'kdf': KDF_PATTERNS,
    'client_side': CLIENT_SIDE_PATTERNS,
    'jwt': JWT_PATTERNS,
    'variables': VARIABLE_NAME_PATTERNS,
    'env_vars': ENV_VAR_PATTERNS
}

def compile_patterns():
    """Compile all regex patterns for efficient matching"""
    compiled = {}
    for category, patterns in ALL_PATTERNS.items():
        compiled[category] = {}
        for name, info in patterns.items():
            compiled[category][name] = {
                'regex': re.compile(info['pattern'], re.IGNORECASE | re.MULTILINE),
                'description': info['description'],
                'severity': info['severity'],
                'cwe': info['cwe']
            }
    return compiled

def get_pattern_categories():
    """Get list of all pattern categories"""
    return list(ALL_PATTERNS.keys())

def get_patterns_by_category(category):
    """Get patterns for a specific category"""
    return ALL_PATTERNS.get(category, {})
