#!/usr/bin/env python3
"""
Debug script to identify why detection pipeline is failing.
This will test each component individually to isolate the problem.
"""

import sys
import os
import json
import asyncio
from pathlib import Path

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

async def test_har_parser():
    """Test if HAR parser can extract data."""
    print("🔍 Testing HAR Parser...")
    
    try:
        from netstealth_analyzer.parsers.har import HarParser
        
        parser = HarParser()
        result = await parser.parse("examples/sample_data/sample_high_risk_session.har")
        
        print(f"✅ Parser created successfully")
        print(f"✅ File parsed successfully")
        print(f"📊 Network traces found: {len(result.network_traces)}")
        
        if result.network_traces:
            trace = result.network_traces[0]
            print(f"📋 First trace metadata keys: {list(trace.metadata.keys())}")
            
            # Check for HTTP data
            http_request = trace.metadata.get('http_request')
            http_response = trace.metadata.get('http_response')
            
            if http_request:
                print(f"🌐 HTTP Request found: {http_request.get('method')} {http_request.get('url')}")
                headers = http_request.get('headers', [])
                print(f"📝 Request headers count: {len(headers)}")
                
                # Look for webdriver header
                webdriver_found = False
                for header in headers:
                    if 'webdriver' in header.get('name', '').lower():
                        print(f"🤖 Found webdriver header: {header}")
                        webdriver_found = True
                        break
                
                if not webdriver_found:
                    print("⚠️  No webdriver header found in first trace")
            else:
                print("❌ No HTTP request data in trace metadata")
            
            if http_response:
                print(f"📨 HTTP Response found: {http_response.get('status_code')}")
                body = http_response.get('body', '')
                if body and len(str(body)) > 0:
                    print(f"📄 Response body length: {len(str(body))}")
                    # Look for automation detection patterns
                    body_str = str(body).lower()
                    if 'automation' in body_str or 'webdriver' in body_str:
                        print(f"🚨 Automation patterns found in response body")
                    else:
                        print(f"ℹ️  No obvious automation patterns in response body")
                else:
                    print("⚠️  No response body data")
            else:
                print("❌ No HTTP response data in trace metadata")
        
        return True
        
    except Exception as e:
        print(f"❌ HAR Parser test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_detector_registry():
    """Test if detector registry has detectors."""
    print("\n🔍 Testing Detector Registry...")
    
    try:
        from netstealth_analyzer.detectors.registry import get_global_registry
        
        registry = get_global_registry()
        print(f"✅ Registry created successfully")
        
        detectors = registry.list_detectors()
        print(f"📋 Registered detectors: {len(detectors)}")
        
        for detector in detectors:
            print(f"   🔧 {detector.name} (enabled: {detector.is_enabled})")
        
        # Test creating browser detector
        browser_detector = registry.create_detector("Browser Configuration Detector")
        if browser_detector:
            print(f"✅ Browser detector created successfully")
        else:
            print(f"❌ Failed to create browser detector")
        
        return len(detectors) > 0
        
    except Exception as e:
        print(f"❌ Detector registry test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_browser_detector_directly():
    """Test browser detector directly with sample data."""
    print("\n🔍 Testing Browser Detector Directly...")
    
    try:
        from netstealth_analyzer.detectors.browser import BrowserDetector
        from netstealth_analyzer.detectors.base import DetectionContext
        from netstealth_analyzer.models.network import NetworkTrace
        
        # Create browser detector
        detector = BrowserDetector()
        print(f"✅ Browser detector created")
        
        # Create fake trace with webdriver header
        trace = NetworkTrace(
            trace_id="test_trace",
            metadata={
                'http_request': {
                    'method': 'GET',
                    'url': 'http://target-service.com/api/user/profile',
                    'headers': [
                        {'name': 'User-Agent', 'value': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'},
                        {'name': 'webdriver', 'value': 'true'},
                        {'name': 'selenium-version', 'value': '4.15.0'}
                    ]
                },
                'http_response': {
                    'status_code': 200,
                    'body': 'automation detected by service'
                }
            }
        )
        
        # Create context
        context = DetectionContext(
            network_traces=[trace],
            service_domains=['target-service.com'],
            confidence_threshold=0.5
        )
        
        # Run detection
        result = await detector.detect(context)
        print(f"✅ Detection completed")
        print(f"📊 Issues found: {len(result.issues_found)}")
        
        for issue in result.issues_found:
            severity = issue.severity.value if hasattr(issue.severity, 'value') else issue.severity
            print(f"   🚨 {issue.title} (severity: {severity})")
        
        return len(result.issues_found) > 0
        
    except Exception as e:
        print(f"❌ Browser detector direct test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_full_pipeline():
    """Test full pipeline with sample file."""
    print("\n🔍 Testing Full Pipeline...")
    
    try:
        # Parse HAR file
        from netstealth_analyzer.parsers.har import HarParser
        parser = HarParser()
        parse_result = await parser.parse("examples/sample_data/sample_high_risk_session.har")
        print(f"✅ HAR file parsed: {len(parse_result.network_traces)} traces")
        
        if not parse_result.network_traces:
            print("❌ No traces found in parse result")
            return False
        
        # Run browser detector on real data
        from netstealth_analyzer.detectors.browser import BrowserDetector
        from netstealth_analyzer.detectors.base import DetectionContext
        
        detector = BrowserDetector()
        context = DetectionContext(
            network_traces=parse_result.network_traces,
            service_domains=['target-service.com'],
            confidence_threshold=0.5
        )
        
        result = await detector.detect(context)
        print(f"✅ Detection completed on real data")
        print(f"📊 Issues found: {len(result.issues_found)}")
        
        for issue in result.issues_found:
            severity = issue.severity.value if hasattr(issue.severity, 'value') else issue.severity
            print(f"   🚨 {issue.title} (severity: {severity}, confidence: {issue.confidence:.2f})")
        
        return len(result.issues_found) > 0
        
    except Exception as e:
        print(f"❌ Full pipeline test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

async def main():
    """Run all diagnostic tests."""
    print("🧪 NetStealth Analyzer - Pipeline Debug Tests")
    print("=" * 60)
    
    test_results = []
    
    # Test 1: HAR Parser
    parser_ok = await test_har_parser()
    test_results.append(("HAR Parser", parser_ok))
    
    # Test 2: Detector Registry
    registry_ok = await test_detector_registry()
    test_results.append(("Detector Registry", registry_ok))
    
    # Test 3: Browser Detector Direct
    detector_ok = await test_browser_detector_directly()
    test_results.append(("Browser Detector (Direct)", detector_ok))
    
    # Test 4: Full Pipeline
    pipeline_ok = await test_full_pipeline()
    test_results.append(("Full Pipeline", pipeline_ok))
    
    # Summary
    print("\n📋 Test Results Summary:")
    print("=" * 40)
    
    all_passed = True
    for test_name, passed in test_results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} {test_name}")
        if not passed:
            all_passed = False
    
    print(f"\n🎯 Overall Result: {'✅ ALL TESTS PASSED' if all_passed else '❌ SOME TESTS FAILED'}")
    
    if not all_passed:
        print("\n🔧 Next Steps:")
        print("1. Fix failing components")
        print("2. Re-run tests to verify fixes")
        print("3. Run main analysis again")

if __name__ == "__main__":
    asyncio.run(main())
