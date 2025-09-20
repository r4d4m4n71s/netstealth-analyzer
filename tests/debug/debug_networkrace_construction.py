#!/usr/bin/env python3
"""
Debug script to test NetworkTrace construction and http_data field.
"""

import asyncio
from datetime import datetime
from pathlib import Path

from src.netstealth_analyzer.models.network import NetworkTrace, HttpData, HttpRequest, HttpResponse, TimingInfo
from src.netstealth_analyzer.models.enums import NetworkProtocol


async def debug_networkrace_construction():
    """Debug NetworkTrace construction and http_data field."""
    print("🔍 Debugging NetworkTrace construction...")
    
    # Create test HTTP data
    request = HttpRequest(
        method="GET",
        url="http://example.com/test",
        headers=[{"name": "Host", "value": "example.com"}],
        body=None,
        timestamp=datetime.now()
    )
    
    response = HttpResponse(
        status_code=200,
        status_text="OK",
        headers=[{"name": "Content-Type", "value": "text/html"}],
        body="<html>Test</html>",
        body_size=18
    )
    
    timing = TimingInfo(
        dns_lookup=10,
        tcp_connect=20,
        ssl_handshake=-1,
        request_sent=5,
        waiting=100,
        content_download=15,
        blocked=0
    )
    
    # Create HttpData
    print("\n📦 Creating HttpData...")
    http_data = HttpData(
        request=request,
        response=response,
        timing=timing
    )
    print(f"   HttpData created: {http_data is not None}")
    print(f"   HttpData request: {http_data.request is not None}")
    print(f"   HttpData response: {http_data.response is not None}")
    print(f"   HttpData timing: {http_data.timing is not None}")
    
    # Test 1: Create NetworkTrace with http_data
    print("\n🧪 Test 1: NetworkTrace with http_data parameter")
    try:
        trace1 = NetworkTrace(
            trace_id="test_1",
            protocol=NetworkProtocol.HTTP,
            http_data=http_data
        )
        print(f"   ✅ NetworkTrace created successfully")
        print(f"   Protocol: {trace1.protocol}")
        print(f"   HTTP data exists: {trace1.http_data is not None}")
        print(f"   is_http(): {trace1.is_http()}")
        
        if trace1.http_data:
            print(f"   HTTP data request URL: {trace1.http_data.request.url}")
            print(f"   HTTP data response status: {trace1.http_data.response.status_code}")
        else:
            print(f"   ❌ HTTP data is None!")
            
    except Exception as e:
        print(f"   ❌ Error creating NetworkTrace: {e}")
    
    # Test 2: Create NetworkTrace with legacy fields
    print("\n🧪 Test 2: NetworkTrace with legacy fields")
    try:
        trace2 = NetworkTrace(
            trace_id="test_2",
            protocol=NetworkProtocol.HTTP,
            request=request,
            response=response,
            timing=timing
        )
        print(f"   ✅ NetworkTrace created successfully")
        print(f"   Protocol: {trace2.protocol}")
        print(f"   HTTP data exists: {trace2.http_data is not None}")
        print(f"   is_http(): {trace2.is_http()}")
        print(f"   Legacy request exists: {hasattr(trace2, 'request') and trace2.request is not None}")
        print(f"   Legacy response exists: {hasattr(trace2, 'response') and trace2.response is not None}")
        
    except Exception as e:
        print(f"   ❌ Error creating NetworkTrace: {e}")
    
    # Test 3: Create NetworkTrace with both http_data and legacy fields
    print("\n🧪 Test 3: NetworkTrace with both http_data and legacy fields")
    try:
        trace3 = NetworkTrace(
            trace_id="test_3",
            protocol=NetworkProtocol.HTTP,
            http_data=http_data,
            request=request,
            response=response,
            timing=timing
        )
        print(f"   ✅ NetworkTrace created successfully")
        print(f"   Protocol: {trace3.protocol}")
        print(f"   HTTP data exists: {trace3.http_data is not None}")
        print(f"   is_http(): {trace3.is_http()}")
        print(f"   Legacy request exists: {hasattr(trace3, 'request') and trace3.request is not None}")
        print(f"   Legacy response exists: {hasattr(trace3, 'response') and trace3.response is not None}")
        
        if trace3.http_data:
            print(f"   HTTP data request URL: {trace3.http_data.request.url}")
            print(f"   HTTP data response status: {trace3.http_data.response.status_code}")
        
    except Exception as e:
        print(f"   ❌ Error creating NetworkTrace: {e}")
    
    # Test 4: Check NetworkTrace model fields
    print("\n🔍 NetworkTrace model inspection:")
    print(f"   Model fields: {list(NetworkTrace.model_fields.keys())}")
    print(f"   Has http_data field: {'http_data' in NetworkTrace.model_fields}")
    
    if 'http_data' in NetworkTrace.model_fields:
        http_data_field = NetworkTrace.model_fields['http_data']
        print(f"   http_data field type: {http_data_field.annotation}")
        print(f"   http_data field required: {http_data_field.is_required()}")
        print(f"   http_data field default: {http_data_field.default}")


if __name__ == "__main__":
    asyncio.run(debug_networkrace_construction())
