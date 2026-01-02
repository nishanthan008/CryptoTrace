"""
Authentication handling for CryptoTrace
"""

import json
import os

class AuthHandler:
    """
    Manages authentication context for the browser
    """
    
    def __init__(self, auth_file=None):
        self.auth_file = auth_file
        self.cookies = []
        self.headers = {}
        self.local_storage = {}
        self.session_storage = {}
        
        if self.auth_file:
            self._load_auth_context()

    def _load_auth_context(self):
        """Load authentication data from file"""
        if not os.path.exists(self.auth_file):
            raise FileNotFoundError(f"Auth file not found: {self.auth_file}")
            
        try:
            with open(self.auth_file, 'r') as f:
                data = json.load(f)
                
            self.cookies = data.get('cookies', [])
            self.headers = data.get('headers', {})
            self.local_storage = data.get('localStorage', {})
            self.session_storage = data.get('sessionStorage', {})
            
            # Basic validation
            if not isinstance(self.cookies, list):
                print("Warning: 'cookies' in auth file must be a list")
                self.cookies = []
            if not isinstance(self.headers, dict):
                print("Warning: 'headers' in auth file must be a dict")
                self.headers = {}
                
        except json.JSONDecodeError:
            raise ValueError(f"Invalid JSON in auth file: {self.auth_file}")
        except Exception as e:
            raise RuntimeError(f"Error loading auth context: {str(e)}")

    def prepare_browser_context(self, context):
        """
        Apply cookies and other settings to Playwright browser context
        
        Args:
            context: Playwright BrowserContext object
        """
        if self.cookies:
            # Playwright expects a list of cookie objects
            # Ensure required fields are present (name, value, url or domain/path)
            clean_cookies = []
            for cookie in self.cookies:
                # Basic sanitation or validation could happen here
                clean_cookies.append(cookie)
            
            try:
                context.add_cookies(clean_cookies)
            except Exception as e:
                print(f"Warning: Failed to add some cookies: {e}")

        # Note: Headers are usually set on the page or request interception level
        # handled by the RuntimeController
        
    def get_headers(self):
        """Return headers to be injected"""
        return self.headers

    def get_storage_scripts(self):
        """
        Generate JavaScript snippets to inject localStorage/sessionStorage
        
        Returns:
            list: List of JS strings to execute
        """
        scripts = []
        
        if self.local_storage:
            for k, v in self.local_storage.items():
                safe_k = json.dumps(k)
                safe_v = json.dumps(v)
                scripts.append(f"window.localStorage.setItem({safe_k}, {safe_v});")
                
        if self.session_storage:
            for k, v in self.session_storage.items():
                safe_k = json.dumps(k)
                safe_v = json.dumps(v)
                scripts.append(f"window.sessionStorage.setItem({safe_k}, {safe_v});")
                
        return scripts
