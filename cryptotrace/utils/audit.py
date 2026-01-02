"""
Audit logging for CryptoTrace usage
"""

import os
import datetime
import json
import uuid

class AuditLogger:
    """
    Logs every execution of the tool for accountability
    """
    
    def __init__(self, log_dir=None):
        if log_dir is None:
            # Default to ~/.cryptotrace/audit.log
            home = os.path.expanduser("~")
            self.log_dir = os.path.join(home, ".cryptotrace")
        else:
            self.log_dir = log_dir
            
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir, exist_ok=True)
            
        self.log_file = os.path.join(self.log_dir, "audit.log")
        self.session_id = str(uuid.uuid4())

    def log_scan_start(self, target_url, authorized, options):
        """
        Log the start of a scan
        """
        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "event": "SCAN_START",
            "session_id": self.session_id,
            "target": target_url,
            "authorized": authorized,
            "options": {k: str(v) for k, v in options.items() if k != 'auth'}, # Don't log full auth details
            "user": os.getlogin()
        }
        self._write_entry(entry)

    def log_scan_end(self, findings_count, duration_seconds, output_file=None):
        """
        Log the completion of a scan
        """
        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "event": "SCAN_END",
            "session_id": self.session_id,
            "findings_count": findings_count,
            "duration_seconds": duration_seconds,
            "output_file": output_file
        }
        self._write_entry(entry)

    def log_error(self, error_message):
        """
        Log an error during execution
        """
        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "event": "ERROR",
            "session_id": self.session_id,
            "error": str(error_message)
        }
        self._write_entry(entry)

    def _write_entry(self, entry):
        """Write entry to log file"""
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            # Fallback to stderr if logging fails, ensure audit availability
            import sys
            print(f"[AUDIT FAILURE] Could not write to audit log: {e}", file=sys.stderr)
            print(f"[AUDIT ENTRY] {json.dumps(entry)}", file=sys.stderr)
