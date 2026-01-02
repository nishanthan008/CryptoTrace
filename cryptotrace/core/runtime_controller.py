"""
Runtime Controller - Manages headless browser automation
"""

import asyncio
from playwright.async_api import async_playwright
import json
import time

class RuntimeController:
    """
    Manages the browser lifecycle and instrumentation
    """
    
    def __init__(self, headless=True, timeout=30000):
        self.headless = headless
        self.timeout = timeout
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None
        self.monitoring_scripts = self._load_monitoring_scripts()

    def _load_monitoring_scripts(self):
        """
        Define scripts to inject for runtime monitoring of Crypto API
        """
        return """
        (() => {
            window.__crypto_observations = [];
            
            function bufferToHex(buffer) {
                if (!buffer) return null;
                return Array.from(new Uint8Array(buffer))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join('');
            }
            
            function logObservation(type, details) {
                window.__crypto_observations.push({
                    type: type,
                    timestamp: Date.now(),
                    details: details,
                    stack: new Error().stack
                });
            }

            // Hook Web Crypto API
            if (window.crypto && window.crypto.subtle) {
                
                // Helper to extract IV/Nonce from params
                function extractIv(algo) {
                    if (!algo) return null;
                    if (algo.iv) return bufferToHex(algo.iv);
                    if (algo.counter) return bufferToHex(algo.counter);
                    if (algo.nonce) return bufferToHex(algo.nonce);
                    return null;
                }

                const originalEncrypt = window.crypto.subtle.encrypt;
                window.crypto.subtle.encrypt = async function(algorithm, key, data) {
                    
                    // Attempt to export key if extractable
                    let keyData = null;
                    if (key.extractable) {
                         try {
                            const raw = await window.crypto.subtle.exportKey("raw", key);
                            keyData = bufferToHex(raw);
                         } catch (e) {
                             // Try JWK if raw fails
                             try {
                                 keyData = await window.crypto.subtle.exportKey("jwk", key);
                             } catch(e2) {}
                         }
                    }

                    logObservation('webcrypto_encrypt', {
                        algorithm: algorithm,
                        iv_hex: extractIv(algorithm),
                        key_usages: key.usages,
                        key_algorithm: key.algorithm,
                        extractable: key.extractable,
                        key_data: keyData
                    });
                    return originalEncrypt.apply(this, arguments);
                };

                const originalDecrypt = window.crypto.subtle.decrypt;
                window.crypto.subtle.decrypt = async function(algorithm, key, data) {
                    let keyData = null;
                    if (key.extractable) {
                         try {
                            const raw = await window.crypto.subtle.exportKey("raw", key);
                            keyData = bufferToHex(raw);
                         } catch (e) {}
                    }
                    
                    logObservation('webcrypto_decrypt', {
                        algorithm: algorithm,
                        iv_hex: extractIv(algorithm),
                        key_usages: key.usages,
                        key_algorithm: key.algorithm,
                        extractable: key.extractable,
                        key_data: keyData
                    });
                    return originalDecrypt.apply(this, arguments);
                };

                const originalImportKey = window.crypto.subtle.importKey;
                window.crypto.subtle.importKey = async function(format, keyData, algorithm, extractable, keyUsages) {
                    let capturedKey = null;
                    
                    if (format === 'raw') {
                        capturedKey = bufferToHex(keyData);
                    } else if (format === 'jwk') {
                        capturedKey = keyData;
                    }

                    logObservation('webcrypto_importKey', {
                        format: format,
                        algorithm: algorithm,
                        extractable: extractable,
                        usages: keyUsages,
                        captured_key: capturedKey 
                    });
                    return originalImportKey.apply(this, arguments);
                };
                
                const originalGenerateKey = window.crypto.subtle.generateKey;
                window.crypto.subtle.generateKey = async function(algorithm, extractable, keyUsages) {
                    const result = await originalGenerateKey.apply(this, arguments);
                    
                    // If extractable, grab it immediately
                    if (extractable) {
                        try {
                            let keyToExport = result;
                            // handle key pairs
                            if (result.privateKey) keyToExport = result.privateKey; 
                            
                            const raw = await window.crypto.subtle.exportKey("jwk", keyToExport); 
                            logObservation('webcrypto_generateKey', {
                                algorithm: algorithm,
                                extractable: extractable,
                                generated_key: raw
                            });
                        } catch(e) {}
                    }
                    return result;
                };
            }
            
            // Hook CryptoJS (IV and Key extraction)
            const checkCryptoJS = setInterval(() => {
                if (window.CryptoJS) {
                    clearInterval(checkCryptoJS);
                    logObservation('library_detected', { name: 'CryptoJS' });
                    
                    if (window.CryptoJS.AES && window.CryptoJS.AES.encrypt) {
                         const originalAESEncrypt = window.CryptoJS.AES.encrypt;
                         window.CryptoJS.AES.encrypt = function(message, key, cfg) {
                             
                             let iv = null;
                             if (cfg && cfg.iv) {
                                 iv = cfg.iv.toString(); 
                             }
                             
                             logObservation('cryptojs_aes_encrypt', {
                                 mode: cfg && cfg.mode ? cfg.mode.name : 'unknown',
                                 padding: cfg && cfg.padding ? cfg.padding.name : 'unknown',
                                 key_hex: key.toString(), 
                                 iv_hex: iv
                             });
                             return originalAESEncrypt.apply(this, arguments);
                         }
                    }
                }
            }, 500);
            
            // Universal Library Detector
            const checkLibs = setInterval(() => {
                const libs = [
                    { name: 'Forge', check: () => window.forge && window.forge.cipher },
                    { name: 'JSEncrypt', check: () => window.JSEncrypt },
                    { name: 'SJCL', check: () => window.sjcl },
                    { name: 'Sodium', check: () => window.sodium }
                ];
                
                libs.forEach(lib => {
                    if (lib.check()) {
                         logObservation('library_detected', { name: lib.name });
                    }
                });
            }, 1000);

        })();
        """

    async def launch_browser(self, auth_handler=None):
        """
        Launch the browser and context
        """
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(
            headless=self.headless,
            args=['--no-sandbox', '--disable-setuid-sandbox']
        )
        self.context = await self.browser.new_context(
            ignore_https_errors=True,
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 CryptoTrace/1.0'
        )
        
        # Enable CDP for strict network monitoring if needed
        # self.cdp = await self.context.new_cdp_session(self.page)
        
        if auth_handler:
            auth_handler.prepare_browser_context(self.context)

        self.page = await self.context.new_page()
        
        # Initialize monitoring script on every navigation
        await self.page.add_init_script(self.monitoring_scripts)
        
        # If auth handler has headers, set them
        if auth_handler and auth_handler.get_headers():
             await self.page.set_extra_http_headers(auth_handler.get_headers())

    async def navigate(self, url):
        """
        Navigate to the target URL and wait for load
        """
        if not self.page:
            raise RuntimeError("Browser not started. Call launch_browser() first.")
            
        try:
            response = await self.page.goto(url, wait_until='networkidle', timeout=self.timeout)
            
            # Inject some scrolling to trigger lazy loads?
            # await self.page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            
            return response
        except Exception as e:
            print(f"Navigation error: {e}")
            return None

    async def get_runtime_observations(self):
        """
        Retrieve observations collected by the injected script
        """
        try:
            return await self.page.evaluate("() => window.__crypto_observations || []")
        except Exception:
            return []

    async def close(self):
        """
        Cleanup resources
        """
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
