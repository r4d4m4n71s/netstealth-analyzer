#!/usr/bin/env python3

import asyncio
import sys
import os

# Add the src directory to Python path
sys.path.insert(0, 'src')

from netstealth_analyzer.models.network import HttpTrace, HttpRequest, HttpResponse
from netstealth_analyzer.parsers.har import HarParser
from netstealth_analyzer.detectors.proxy import ProxyDetector
from netstealth_analyzer.detectors.base import DetectionContext

async def debug_httptrace():
    print("🔬 Debug: Testing HttpTrace creation and proxy detection...")
    
    # Test 1: Create HttpTrace manually
    print("\n1️⃣ Testing manual HttpTrace creation:")
    request = HttpRequest(
        method="GET",
        url="https://example.com/test",
        headers=[{"name": "X-Forwarded-For", "value": "198.51.100.42"}],
        body=None
    )
    
    response = HttpResponse(
        status_code=200,
        status_text="OK",
        headers=[],
        body="proxy detected - using datacenter ip",
        body_size=100
    )
    
    trace = HttpTrace(
        trace_id="debug_001",
        request=request,
        response=response,
        metadata={}
    )
    
    print(f"✅ HttpTrace created: {trace.trace_id}")
    print(f"✅ Has request: {trace.request is not None}")
    print(f"✅ Has response: {trace.response is not None}")
    print(f"✅ Request URL: {trace.request.url}")
    print(f"✅ Response body: {trace.response.body[:50]}...")
    
    # Test 2: Test proxy detector on this trace
    print("\n2️⃣ Testing proxy detector:")
    detector = ProxyDetector()
    context = DetectionContext(
        network_traces=[trace],
        service_domains=[],
        confidence_threshold=0.5
    )
    
    result = await detector.detect(context)
    print(f"✅ Detection complete!")
    print(f"✅ Issues found: {len(result.issues_found)}")
    for issue in result.issues_found:
        print(f"   - {issue.title} (Severity: {issue.severity})")
    
    # Test 3: Parse HAR file and check traces
    print("\n3️⃣ Testing HAR parser:")
    parser = HarParser()
    
    try:
        parse_result = await parser.parse("examples/sample_data/sample_high_risk_session.har")
        print(f"✅ HAR parsing complete!")
        print(f"✅ Traces parsed: {len(parse_result.network_traces)}")
        
        if parse_result.network_traces:
            first_trace = parse_result.network_traces[0]
            print(f"✅ First trace type: {type(first_trace).__name__}")
            print(f"✅ First trace has request: {hasattr(first_trace, 'request') and first_trace.request is not None}")
            print(f"✅ First trace has response: {hasattr(first_trace, 'response') and first_trace.response is not None}")
            
            if hasattr(first_trace, 'request') and first_trace.request:
                print(f"✅ First trace URL: {first_trace.request.url}")
                print(f"✅ First trace headers count: {len(first_trace.request.headers)}")
                
            # Test detector on parsed traces
            print("\n4️⃣ Testing detector on parsed traces:")
            detector_context = DetectionContext(
                network_traces=parse_result.network_traces[:5],  # Test first 5 traces
                service_domains=[],
                confidence_threshold=0.5
            )
            
            detector_result = await detector.detect(detector_context)
            print(f"✅ Detector result: {len(detector_result.issues_found)} issues found")
            for issue in detector_result.issues_found:
                print(f"   - {issue.title} (Severity: {issue.severity})")
        
    except Exception as e:
        print(f"❌ HAR parsing failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(debug_httptrace())
