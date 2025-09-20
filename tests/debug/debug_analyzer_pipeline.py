#!/usr/bin/env python3
"""
Debug script to analyze the full analyzer pipeline and identify where issues are lost.
"""

import asyncio
from pathlib import Path

from src.netstealth_analyzer.builder import AnalyzerBuilder


async def debug_analyzer_pipeline():
    """Debug the full analyzer pipeline to see where issues are lost."""
    print("🔍 Debugging full analyzer pipeline...")
    
    # Build analyzer using the same method as test_high_risk_verification.py
    har_file = Path("examples/sample_data/sample_high_risk_session.har")
    
    print(f"\n🏗️ Building analyzer...")
    builder = AnalyzerBuilder()
    analyzer = builder.with_log(har_file).for_service("target-service.com").build()
    
    print(f"   Built analyzer with {len(analyzer._detectors)} detectors")
    for i, detector in enumerate(analyzer._detectors):
        print(f"   Detector {i+1}: {type(detector).__name__}")
    
    print(f"\n⚙️ Running analysis...")
    result = await analyzer.analyze()
    
    print(f"\n📊 Analysis Results:")
    print(f"   Overall Score: {result.summary.overall_score}/100")
    print(f"   Status: {result.summary.status}")
    print(f"   Total Issues: {len(result.issues)}")
    print(f"   Network Traces: {len(result.network_traces)}")
    
    # Debug the analysis process step by step
    print(f"\n🔍 Debugging analysis process...")
    
    # Check if network traces were parsed correctly
    print(f"   Network traces parsed: {len(result.network_traces)}")
    for i, trace in enumerate(result.network_traces):
        print(f"   Trace {i+1}: {trace.protocol}, HTTP data: {trace.is_http()}")
        if trace.is_http() and trace.http_data:
            print(f"      URL: {trace.http_data.request.url if trace.http_data.request else 'No request'}")
    
    # Check if issues were found but not added to result
    print(f"\n🔍 Checking individual detector results...")
    
    # Test each detector individually
    from src.netstealth_analyzer.detectors.base import DetectionContext
    
    if result.network_traces:
        context = DetectionContext(
            network_traces=result.network_traces,
            service_domains=["target-service.com"],
            confidence_threshold=0.5
        )
        
        for i, detector in enumerate(analyzer._detectors):
            print(f"\n   Testing {type(detector).__name__}...")
            try:
                detection_result = await detector.detect(context)
                print(f"      Issues found: {len(detection_result.issues_found)}")
                
                for issue in detection_result.issues_found:
                    severity = issue.severity.value.upper() if hasattr(issue.severity, 'value') else str(issue.severity).upper()
                    print(f"      - [{severity}] {issue.title}")
                    
            except Exception as e:
                print(f"      ❌ Error: {e}")
    
    # Check if the issue is in the analyzer's _direct_analysis method
    print(f"\n🔍 Checking analyzer's _direct_analysis method...")
    
    # Let's examine the analyzer's internal state
    print(f"   Analyzer parsers: {len(analyzer._parsers)}")
    print(f"   Analyzer detectors: {len(analyzer._detectors)}")
    print(f"   Analyzer log files: {len(analyzer._log_files)}")
    
    # Check if the issue is in result processing
    print(f"\n🔍 Final result summary:")
    print(f"   Result ID: {result.result_id}")
    print(f"   Issues in result: {len(result.issues)}")
    print(f"   Network traces in result: {len(result.network_traces)}")
    
    if result.issues:
        print(f"   Issues found:")
        for issue in result.issues:
            print(f"   - {issue.title}")
    else:
        print(f"   ❌ No issues in final result!")


if __name__ == "__main__":
    asyncio.run(debug_analyzer_pipeline())
