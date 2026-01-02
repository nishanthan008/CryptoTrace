"""
CryptoTrace CLI - Main Entry Point
"""

import asyncio
import argparse
import sys
import uuid
from datetime import datetime
import os
import signal
import sys

# Core imports
from .core.runtime_controller import RuntimeController
from .core.collector import Collector
from .core.detector import Detector
from .core.analyzer import Analyzer
from .core.reporter import Reporter

# Utils imports
from .utils.auth import AuthHandler
from .utils.redaction import Redactor
from .utils.audit import AuditLogger

async def run_scan(args):
    """
    Orchestrate the scanning process
    """
    scan_id = str(uuid.uuid4())
    print(f"[*] Starting CryptoTrace Scan (ID: {scan_id})")
    print(f"[*] Target: {args.url}")
    
    # Initialize components
    audit = AuditLogger()
    audit.log_scan_start(args.url, args.authorized, vars(args))
    
    auth_handler = AuthHandler(args.auth) if args.auth else None
    
    redactor = Redactor(enabled=not args.no_redact_secrets)
    
    runtime = RuntimeController(
        headless=args.headless, 
        timeout=int(args.timeout) * 1000
    )
    
    collector = Collector(runtime)
    detector = Detector()
    analyzer = Analyzer(redactor=redactor)
    
    start_time = datetime.now()
    
    try:
        # 1. Launch & Navigate
        print("[*] Launching browser environment...")
        await runtime.launch_browser(auth_handler=auth_handler)
        
        collector_task = collector.start_monitoring()
        
        print(f"[*] Navigating to {args.url}...")
        response = await runtime.navigate(args.url)
        
        if not response:
            print("[-] Failed to load target URL")
            return
            
        print("[*] Page loaded. Collecting assets...")
        
        # 2. Collect Data
        # Wait a bit for dynamic content
        await asyncio.sleep(5) 
        
        if args.capture_network:
            print("[*] Capturing network traffic...")
            
        await collector.collect_page_scripts()
        await collector.inspect_storage()
        
        print("[*] Gathering runtime observations...")
        raw_data = await collector.get_runtime_data()
        
        # 3. Detect
        print("[*] Analyzing cryptographic usage...")
        all_findings = []
        
        # Analyze Scripts
        for script in raw_data['scripts']:
            loc_info = {"url": script['url'], "type": "script"}
            findings = detector.scan_content(script['content'], loc_info)
            all_findings.extend(findings)
            
        # Analyze Storage
        storage_findings = detector.scan_storage(raw_data['storage'])
        all_findings.extend(storage_findings)
        
        # Analyze Runtime Observations
        if args.capture_runtime:
            runtime_findings = detector.analyze_runtime_observations(raw_data['observations'])
            all_findings.extend(runtime_findings)
            
        # 4. Analyze & Correlate
        print(f"[*] Correlating {len(all_findings)} potential findings...")
        analyzed_findings = analyzer.process_findings(all_findings)
        summary = analyzer.generate_summary(analyzed_findings)
        
        # 5. Report
        scan_result = {
            "scan_id": scan_id,
            "target": args.url,
            "timestamp": datetime.now().isoformat(),
            "summary": summary,
            "findings": analyzed_findings
        }
        
        reporter = Reporter(scan_result)
        
        # Default report name if not provided
        base_name = f"cryptotrace_report_{scan_id[:8]}"
        
        if args.report:
            fmts = args.report.split(',')
            for fmt in fmts:
                fname = args.output if args.output else f"{base_name}.{fmt}"
                if fmt == 'json':
                    reporter.save_json(fname)
                elif fmt == 'sarif':
                    reporter.save_sarif(fname)
                elif fmt == 'markdown':
                    reporter.save_markdown(fname)
        else:
            # Default to JSON
            fname = args.output if args.output else f"{base_name}.json"
            reporter.save_json(fname)
            
        # Console Summary
        print("\n" + "="*50)
        print("SCAN COMPLETE")
        print("="*50)
        print(f"Total Findings: {summary['total_findings']}")
        print(f"CRITICAL: {summary['critical']}")
        print(f"HIGH:     {summary['high']}")
        print(f"MEDIUM:   {summary['medium']}")
        print(f"LOW:      {summary['low']}")
        print("="*50)
        
        duration = (datetime.now() - start_time).total_seconds()
        audit.log_scan_end(summary['total_findings'], duration, args.output)
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"\n[!] Error during scan: {e}")
        import traceback
        traceback.print_exc()
        audit.log_error(str(e))
    finally:
        print("[*] Cleaning up resources...")
        await runtime.close()

def main():
    parser = argparse.ArgumentParser(description="CryptoTrace - Web Crypto Security Scanner")
    
    # Required
    parser.add_argument("--url", required=True, help="Target application URL")
    parser.add_argument("--authorized", action="store_true", required=True, help="Explicit authorization acknowledgment")
    
    # Options
    parser.add_argument("--auth", help="Authentication context file (JSON)")
    parser.add_argument("--headless", action="store_true", default=True, help="Run browser in headless mode (default: True)")
    parser.add_argument("--no-headless", action="store_false", dest="headless", help="Run browser in visible mode")
    parser.add_argument("--capture-network", action="store_true", default=True, help="Capture HTTP/HTTPS traffic")
    parser.add_argument("--capture-runtime", action="store_true", default=True, help="Observe crypto functions at runtime")
    parser.add_argument("--timeout", default=300, type=int, help="Scan timeout in seconds")
    parser.add_argument("--report", default="json", help="Output format (json, sarif, markdown)")
    parser.add_argument("--output", help="Save report to file path")
    parser.add_argument("--no-redact-secrets", action="store_true", help="Disable secret redaction (DANGEROUS)")
    
    # Detection Toggles (Enable all by default for MVP simplicity, or filter if flags provided)
    parser.add_argument("--detect-keys", action="store_true", help="Detect encryption keys")
    parser.add_argument("--detect-iv", action="store_true", help="Detect IV usage")
    parser.add_argument("--detect-algorithms", action="store_true", help="Identify algorithms")

    args = parser.parse_args()
    
    if not args.authorized:
        print("ERROR: --authorized flag is required. You must have explicit permission to scan the target.")
        sys.exit(1)

    if sys.platform == 'win32':
        # Windows specific event loop policy
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    asyncio.run(run_scan(args))

if __name__ == "__main__":
    main()
