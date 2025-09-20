#!/usr/bin/env python3
"""
Debug script to understand edge case test failures.
"""

import asyncio
from unittest.mock import Mock
from netstealth_analyzer.detectors.tls import TlsDetector
from netstealth_analyzer.detectors.base import DetectionContext
from netstealth_analyzer.models.network import NetworkTrace, TLSInfo, ConnectionInfo
from netstealth_analyzer.models.enums import TLSVersion

async def debug_alternative_tls_location():
    """Debug alternative TLS info location test."""
    print("=== Debugging Alternative TLS Info Location ===")
    
    # Create detector
    detector = TlsDetector()
    
    # Create TLS info with weak version
    tls_info = TLSInfo(
        version=TLSVersion.TLS_12,  # Start with valid version
        cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    )
    
    # Set version to string (as the test does)
    tls_info.version = "SSLv2"  # This should trigger detection
    
    print(f"TLS Info version: {tls_info.version}")
    print(f"TLS Info version type: {type(tls_info.version)}")
    
    # Create mock network trace
    trace = Mock(spec=NetworkTrace)
    trace.trace_id = "test-trace-edge"
    
    # Set connection_info.tls_info to None (as test does)
    connection_info = Mock(spec=ConnectionInfo)
    connection_info.tls_info = None
    trace.connection_info = connection_info
    
    # Set tls_info directly on trace (alternative location)
    trace.tls_info = tls_info
    
    print(f"Trace connection_info.tls_info: {trace.connection_info.tls_info}")
    print(f"Trace tls_info: {trace.tls_info}")
    
    # Test the detector's TLS info extraction logic
    print("\n--- Testing TLS info extraction ---")
    if hasattr(trace, 'connection_info') and trace.connection_info and hasattr(trace.connection_info, 'tls_info'):
        extracted_tls_info = trace.connection_info.tls_info
        print(f"Found TLS info in connection_info: {extracted_tls_info}")
    elif hasattr(trace, 'tls_info'):
        extracted_tls_info = trace.tls_info
        print(f"Found TLS info in alternative location: {extracted_tls_info}")
    else:
        extracted_tls_info = None
        print("No TLS info found")
    
    if extracted_tls_info:
        print(f"Extracted TLS version: {extracted_tls_info.version}")
        version_str = extracted_tls_info.version.value if hasattr(extracted_tls_info.version, 'value') else str(extracted_tls_info.version)
        print(f"Version string: {version_str}")
        print(f"Is in weak versions: {version_str in detector.weak_tls_versions}")
        print(f"Weak versions list: {detector.weak_tls_versions}")
    
    # Create detection context
    context = DetectionContext(
        network_traces=[trace],
        service_domains=["example.com"],
        confidence_threshold=0.7
    )
    
    # Run detection
    result = await detector.detect(context)
    
    print(f"\nDetection result:")
    print(f"Issues found: {len(result.issues_found)}")
    for issue in result.issues_found:
        print(f"  - {issue.title}: {issue.description}")
    
    return result

async def main():
    """Main debug function."""
    await debug_alternative_tls_location()

if __name__ == "__main__":
    asyncio.run(main())
