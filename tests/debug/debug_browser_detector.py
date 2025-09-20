#!/usr/bin/env python3
"""
Debug script to test BrowserDetector specifically.
"""

import sys
import os
import asyncio

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from netstealth_analyzer import NetStealthAnalyzer

async def debug_browser_detector():
    """Debug the BrowserDetector specifically."""
    
    print("🔬 Debug: BrowserDetector Analysis")
    print("=" * 50)
    
    # Build analyzer with just BrowserDetector
    builder = NetStealthAnalyzer.create()
    builder = builder.with_logs("examples/sample_data/sample_high_risk_session.har")
    
    # Add only BrowserDetector for focused testing
    from src.netstealth_analyzer.detectors.browser import BrowserDetector
    from src.netstealth_analyzer.core.events import EventBus
    
    event_bus = EventBus()
    browser_detector = BrowserDetector(event_bus=event_bus)
    
    # Build analyzer manually to control detectors
    analyzer = builder.build()
    
    # Run analysis
    print("⚙️ Running analysis...")
    results = await analyzer.analyze()
    
    print(f"\n📊 Analysis Results:")
    print(f"   Total Issues: {len(results.issues)}")
    
    # Show all issues with details
    for i, issue in enumerate(results.issues, 1):
        severity_str = str(issue.severity).upper()
        category_str = str(issue.category)
        print(f"   {i:2d}. [{severity_str:8s}] {category_str} - {issue.description}")
        
        # Show evidence if available
        if hasattr(issue, 'evidence') and issue.evidence:
            for j, evidence in enumerate(issue.evidence):
                print(f"       Evidence {j+1}: {evidence.description}")
                if hasattr(evidence, 'value'):
                    print(f"                   Value: {evidence.value}")
    
    # Debug: Check what data the detectors are receiving
    print(f"\n🔍 Debug: Network Traces Analysis")
    print(f"   Network traces count: {len(results.network_traces)}")
    
    for i, trace in enumerate(results.network_traces):
        print(f"\n   Trace {i+1}:")
        print(f"     Trace ID: {trace.trace_id}")
        print(f"     Has HttpTrace fields: request={hasattr(trace, 'request')}, response={hasattr(trace, 'response')}")
        
        # Check metadata
        if hasattr(trace, 'metadata') and trace.metadata:
            print(f"     Metadata keys: {list(trace.metadata.keys())}")
            
            # Check HTTP request data
            if 'http_request' in trace.metadata:
                http_req = trace.metadata['http_request']
                print(f"     HTTP Request URL: {http_req.get('url', 'N/A')}")
                
                # Check for automation headers
                headers = http_req.get('headers', [])
                automation_headers = []
                for header in headers:
                    header_name = header.get('name', '').lower()
                    if any(auto_header in header_name for auto_header in ['webdriver', 'selenium', 'automation']):
                        automation_headers.append(f"{header.get('name')}: {header.get('value')}")
                
                if automation_headers:
                    print(f"     🚨 Automation Headers Found:")
                    for ah in automation_headers:
                        print(f"       - {ah}")
                
                # Check User-Agent
                user_agent = None
                for header in headers:
                    if header.get('name', '').lower() == 'user-agent':
                        user_agent = header.get('value')
                        break
                
                if user_agent:
                    print(f"     User-Agent: {user_agent}")
                    if 'headless' in user_agent.lower():
                        print(f"     🚨 HEADLESS DETECTED in User-Agent!")
            
            # Check HTTP response data
            if 'http_response' in trace.metadata:
                http_resp = trace.metadata['http_response']
                print(f"     HTTP Response Status: {http_resp.get('status_code', 'N/A')}")
                
                # Check response body for automation detection
                body = http_resp.get('body', '')
                if body and isinstance(body, str):
                    if 'automation' in body.lower():
                        print(f"     🚨 AUTOMATION DETECTED in response body!")
                    if 'fingerprint' in body.lower():
                        print(f"     🚨 FINGERPRINTING DETECTED in response body!")

if __name__ == "__main__":
    asyncio.run(debug_browser_detector())
