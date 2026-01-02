"""
Known cryptographic library signatures and detection patterns
"""

# CryptoJS library signatures
CRYPTOJS_SIGNATURES = {
    'library_import': [
        'CryptoJS',
        'crypto-js',
        'cryptojs'
    ],
    'functions': [
        'CryptoJS.AES',
        'CryptoJS.DES',
        'CryptoJS.TripleDES',
        'CryptoJS.RC4',
        'CryptoJS.Rabbit',
        'CryptoJS.MD5',
        'CryptoJS.SHA1',
        'CryptoJS.SHA256',
        'CryptoJS.SHA512',
        'CryptoJS.PBKDF2',
        'CryptoJS.enc.Base64',
        'CryptoJS.enc.Hex',
        'CryptoJS.lib.WordArray'
    ],
    'modes': [
        'CryptoJS.mode.CBC',
        'CryptoJS.mode.CFB',
        'CryptoJS.mode.CTR',
        'CryptoJS.mode.OFB',
        'CryptoJS.mode.ECB'
    ],
    'padding': [
        'CryptoJS.pad.Pkcs7',
        'CryptoJS.pad.Iso97971',
        'CryptoJS.pad.AnsiX923',
        'CryptoJS.pad.Iso10126',
        'CryptoJS.pad.ZeroPadding',
        'CryptoJS.pad.NoPadding'
    ]
}

# Web Crypto API signatures
WEBCRYPTO_SIGNATURES = {
    'api_access': [
        'window.crypto',
        'crypto.subtle',
        'window.crypto.subtle'
    ],
    'functions': [
        'crypto.subtle.encrypt',
        'crypto.subtle.decrypt',
        'crypto.subtle.sign',
        'crypto.subtle.verify',
        'crypto.subtle.digest',
        'crypto.subtle.generateKey',
        'crypto.subtle.deriveKey',
        'crypto.subtle.deriveBits',
        'crypto.subtle.importKey',
        'crypto.subtle.exportKey',
        'crypto.subtle.wrapKey',
        'crypto.subtle.unwrapKey',
        'crypto.getRandomValues'
    ],
    'algorithms': [
        'AES-CBC',
        'AES-CTR',
        'AES-GCM',
        'AES-KW',
        'RSA-OAEP',
        'RSA-PSS',
        'RSASSA-PKCS1-v1_5',
        'ECDSA',
        'ECDH',
        'HMAC',
        'PBKDF2',
        'HKDF'
    ]
}

# Node-forge library signatures
FORGE_SIGNATURES = {
    'library_import': [
        'node-forge',
        'forge'
    ],
    'functions': [
        'forge.cipher.createCipher',
        'forge.cipher.createDecipher',
        'forge.aes',
        'forge.des',
        'forge.rc2',
        'forge.md.md5',
        'forge.md.sha1',
        'forge.md.sha256',
        'forge.md.sha512',
        'forge.hmac',
        'forge.pkcs5.pbkdf2',
        'forge.random',
        'forge.util.encode64',
        'forge.util.decode64'
    ]
}

# sjcl (Stanford JavaScript Crypto Library) signatures
SJCL_SIGNATURES = {
    'library_import': [
        'sjcl'
    ],
    'functions': [
        'sjcl.encrypt',
        'sjcl.decrypt',
        'sjcl.cipher.aes',
        'sjcl.mode.ccm',
        'sjcl.mode.ocb2',
        'sjcl.mode.gcm',
        'sjcl.hash.sha256',
        'sjcl.misc.pbkdf2',
        'sjcl.random'
    ]
}

# JSEncrypt (RSA library) signatures
JSENCRYPT_SIGNATURES = {
    'library_import': [
        'JSEncrypt',
        'jsencrypt'
    ],
    'functions': [
        'JSEncrypt',
        'setPublicKey',
        'setPrivateKey',
        'encrypt',
        'decrypt'
    ]
}

# asmCrypto signatures
ASMCRYPTO_SIGNATURES = {
    'library_import': [
        'asmCrypto'
    ],
    'functions': [
        'asmCrypto.AES_CBC',
        'asmCrypto.AES_GCM',
        'asmCrypto.RSA',
        'asmCrypto.SHA256',
        'asmCrypto.HMAC_SHA256',
        'asmCrypto.PBKDF2_HMAC_SHA256'
    ]
}

# TweetNaCl signatures
TWEETNACL_SIGNATURES = {
    'library_import': [
        'nacl',
        'tweetnacl'
    ],
    'functions': [
        'nacl.secretbox',
        'nacl.box',
        'nacl.sign',
        'nacl.hash',
        'nacl.randomBytes'
    ]
}

# All library signatures combined
ALL_LIBRARIES = {
    'CryptoJS': CRYPTOJS_SIGNATURES,
    'WebCrypto': WEBCRYPTO_SIGNATURES,
    'Forge': FORGE_SIGNATURES,
    'SJCL': SJCL_SIGNATURES,
    'JSEncrypt': JSENCRYPT_SIGNATURES,
    'asmCrypto': ASMCRYPTO_SIGNATURES,
    'TweetNaCl': TWEETNACL_SIGNATURES
}

def detect_crypto_libraries(code):
    """
    Detect which cryptographic libraries are used in the code
    
    Args:
        code (str): JavaScript code to analyze
        
    Returns:
        list: List of detected library names
    """
    detected = []
    
    for lib_name, signatures in ALL_LIBRARIES.items():
        # Check library imports
        for import_sig in signatures.get('library_import', []):
            if import_sig in code:
                detected.append(lib_name)
                break
        
        # Check function usage
        if lib_name not in detected:
            for func_sig in signatures.get('functions', [])[:5]:  # Check first 5 functions
                if func_sig in code:
                    detected.append(lib_name)
                    break
    
    return detected

def get_library_functions(library_name):
    """
    Get all known functions for a specific library
    
    Args:
        library_name (str): Name of the library
        
    Returns:
        list: List of function signatures
    """
    lib_data = ALL_LIBRARIES.get(library_name, {})
    return lib_data.get('functions', [])

def is_weak_algorithm(algorithm):
    """
    Check if an algorithm is considered weak or broken
    
    Args:
        algorithm (str): Algorithm name
        
    Returns:
        tuple: (is_weak, reason)
    """
    weak_algorithms = {
        'MD5': 'Cryptographically broken, vulnerable to collision attacks',
        'SHA1': 'Weak, deprecated for cryptographic use',
        'SHA-1': 'Weak, deprecated for cryptographic use',
        'DES': 'Obsolete, 56-bit key is too small',
        'RC4': 'Broken stream cipher, multiple vulnerabilities',
        'ECB': 'Insecure block cipher mode, reveals patterns',
        '3DES': 'Deprecated, slow and limited security',
        'TripleDES': 'Deprecated, slow and limited security'
    }
    
    for weak_alg, reason in weak_algorithms.items():
        if weak_alg.lower() in algorithm.lower():
            return (True, reason)
    
    return (False, None)

def get_recommended_algorithm(weak_algorithm):
    """
    Get recommended replacement for weak algorithms
    
    Args:
        weak_algorithm (str): Weak algorithm name
        
    Returns:
        str: Recommended alternative
    """
    recommendations = {
        'MD5': 'SHA-256 or SHA-3',
        'SHA1': 'SHA-256 or SHA-3',
        'DES': 'AES-256',
        'RC4': 'AES-GCM or ChaCha20-Poly1305',
        'ECB': 'CBC, CTR, or GCM mode',
        '3DES': 'AES-256',
        'TripleDES': 'AES-256'
    }
    
    for weak_alg, recommendation in recommendations.items():
        if weak_alg.lower() in weak_algorithm.lower():
            return recommendation
    
    return 'Modern authenticated encryption (e.g., AES-GCM, ChaCha20-Poly1305)'
