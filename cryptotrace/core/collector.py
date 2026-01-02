"""
Data Collector - Gathers static and runtime data
"""

import asyncio
from urllib.parse import urljoin

class Collector:
    """
    Collects application assets and runtime data
    """
    
    def __init__(self, runtime_controller):
        self.runtime = runtime_controller
        self.scripts = []
        self.network_traffic = []
        self.storage_data = {}
        
    async def start_monitoring(self):
        """Start network monitoring"""
        self.runtime.page.on("request", self._handle_request)
        self.runtime.page.on("response", self._handle_response)

    def _handle_request(self, request):
        if request.resource_type in ["script", "xhr", "fetch"]:
            self.network_traffic.append({
                "type": "request",
                "url": request.url,
                "method": request.method,
                "headers": request.headers,
                "post_data": request.post_data
            })

    async def _handle_response(self, response):
        try:
            # We are interested in JS files to scan
            if response.request.resource_type == "script":
                text = await response.text()
                self.scripts.append({
                    "url": response.url,
                    "content": text,
                    "type": "external_script"
                })
        except Exception:
            pass # Ignore failures to read body

    async def collect_page_scripts(self):
        """
        Extract inline scripts from the page
        """
        inline_scripts = await self.runtime.page.evaluate("""() => {
            return Array.from(document.scripts)
                .filter(s => !s.src)
                .map(s => s.innerText);
        }""")
        
        for idx, content in enumerate(inline_scripts):
            self.scripts.append({
                "url": f"inline_script_{idx}",
                "content": content,
                "type": "inline_script"
            })
            
        return self.scripts

    async def inspect_storage(self):
        """
        Read localStorage and sessionStorage
        """
        storage = await self.runtime.page.evaluate("""() => {
            return {
                localStorage: {...localStorage},
                sessionStorage: {...sessionStorage}
            };
        }""")
        self.storage_data = storage
        return storage

    async def get_runtime_data(self):
        """
        Get all collected data
        """
        return {
            "scripts": self.scripts,
            "network": self.network_traffic,
            "storage": self.storage_data,
            "observations": await self.runtime.get_runtime_observations()
        }
