#!/usr/bin/env python3
"""
Debug script to analyze HAR parsing and data structure.
"""

import asyncio
import json
from pathlib import Path

from src.netstealth_analyzer.parsers.har import HarParser
from src.netstealth_analyzer.detectors.proxy import ProxyDetector
from src.netstealth_analyzer.detectors.base import DetectionContext


async def debug_har_parsing():
    """Debug HAR parsing and data structure."""
    print("🔍 Debugging HAR parsing and data structure...")
    
    # Load the HAR file directly
    har_file = Path("examples/sample_data/sample_high_risk_session.har")
    
    # Create HAR parser
    parser = HarParser(service_domains=["target-service.com"])
    
    # Parse the HAR file
    print(f"\n📁 Parsing {har_file}...")
    parse_result = await parser.parse(har_file)
    
    print(f"\n📊 Parsed {len(parse_result.network_traces)} traces")
    
    for i, trace in enumerate(parse_result.network_traces):
        print(f"\n🔍 Trace {i+1}:")
        print(f"   Protocol: {trace.protocol}")
        print(f"   Has HTTP data: {trace.is_http()}")
        print(f"   HTTP data exists: {trace.http_data is not None}")
        
        # Check legacy fields
        if hasattr(trace, 'request') and trace.request:
            print(f"   Legacy request URL: {trace.request.url}")
            print(f"   Legacy request headers: {len(trace.request.headers) if trace.request.headers else 0}")
            if trace.request.headers:
                proxy_headers = []
                for header in trace.request.headers:
                    header_name = header.get('name', '').lower()
                    if any(ph in header_name for ph in ['forwarded', 'real-ip', 'via', 'proxy']):
                        proxy_headers.append(f"{header.get('name')}: {header.get('value')}")
                if proxy_headers:
                    print(f"   🚨 Legacy proxy headers found:")
                    for ph in proxy_headers:
                        print(f"      - {ph}")
        
        if hasattr(trace, 'response') and trace.response:
            print(f"   Legacy response status: {trace.response.status_code}")
            print(f"   Legacy response body length: {len(str(trace.response.body)) if trace.response.body else 0}")
            if trace.response.body:
                body_str = str(trace.response.body).lower()
                proxy_indicators = ['proxy', 'datacenter', 'vpn', 'automation', 'detected']
                found_indicators = [ind for ind in proxy_indicators if ind in body_str]
                if found_indicators:
                    print(f"   🚨 Legacy proxy indicators in response: {found_indicators}")
        
        # Check protocol-specific data
        if trace.http_data:
            print(f"   ✅ HTTP data available")
            if trace.http_data.request:
                print(f"      Protocol request URL: {trace.http_data.request.url}")
                print(f"      Protocol request headers: {len(trace.http_data.request.headers) if trace.http_data.request.headers else 0}")
                if trace.http_data.request.headers:
                    proxy_headers = []
                    for header in trace.http_data.request.headers:
                        header_name = header.get('name', '').lower()
                        if any(ph in header_name for ph in ['forwarded', 'real-ip', 'via', 'proxy']):
                            proxy_headers.append(f"{header.get('name')}: {header.get('value')}")
                    if proxy_headers:
                        print(f"      🚨 Protocol proxy headers found:")
                        for ph in proxy_headers:
                            print(f"         - {ph}")
            if trace.http_data.response:
                print(f"      Protocol response status: {trace.http_data.response.status_code}")
                print(f"      Protocol response body length: {len(str(trace.http_data.response.body)) if trace.http_data.response.body else 0}")
                if trace.http_data.response.body:
                    body_str = str(trace.http_data.response.body).lower()
                    proxy_indicators = ['proxy', 'datacenter', 'vpn', 'automation', 'detected']
                    found_indicators = [ind for ind in proxy_indicators if ind in body_str]
                    if found_indicators:
                        print(f"      🚨 Protocol proxy indicators in response: {found_indicators}")
        else:
            print(f"   ❌ No HTTP data available")
        
        print(f"   Trace attributes: {[attr for attr in dir(trace) if not attr.startswith('_')]}")
    
    # Test proxy detector
    print(f"\n🔍 Testing ProxyDetector...")
    detector = ProxyDetector()
    
    context = DetectionContext(
        network_traces=parse_result.network_traces,
        service_domains=["target-service.com"],
        confidence_threshold=0.5
    )
    
    detection_result = await detector.detect(context)
    print(f"   Issues found: {len(detection_result.issues_found)}")
    
    for issue in detection_result.issues_found:
        severity = issue.severity.value.upper() if hasattr(issue.severity, 'value') else str(issue.severity).upper()
        print(f"   - [{severity}] {issue.title}")
        print(f"     {issue.description}")


if __name__ == "__main__":
    asyncio.run(debug_har_parsing())
