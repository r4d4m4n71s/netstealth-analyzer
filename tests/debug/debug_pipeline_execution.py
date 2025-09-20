#!/usr/bin/env python3

import asyncio
import sys
import os
import logging

# Add the src directory to Python path
sys.path.insert(0, 'src')

# Configure detailed logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

from netstealth_analyzer import NetStealthAnalyzer

async def debug_pipeline():
    print("🔬 Debug: Tracing pipeline execution...")
    
    try:
        # Create analyzer the same way the test does
        print("Building analyzer...")
        analyzer = (NetStealthAnalyzer.create()
                    .with_log("examples/sample_data/sample_high_risk_session.har")
                    .build())
        
        print(f"\n📋 Analyzer Details:")
        print(f"   Log files: {len(analyzer._log_files)}")
        print(f"   Parsers: {len(analyzer._parsers)}")
        print(f"   Detectors: {len(analyzer._detectors)}")
        for i, detector in enumerate(analyzer._detectors):
            print(f"      {i+1}: {type(detector).__name__}")
        
        # Initialize manually to see what happens
        print(f"\n🔄 Initializing analyzer...")
        await analyzer.initialize()
        
        # Check pipeline stages
        pipeline = analyzer._pipeline
        print(f"\n🔧 Pipeline Details:")
        print(f"   Total stages: {len(pipeline._stages)}")
        print(f"   Stage order: {pipeline.get_stage_order()}")
        
        for stage_name in pipeline.get_stage_order():
            stage = pipeline._stages[stage_name]
            print(f"   Stage '{stage_name}': {type(stage.component).__name__}")
        
        # Test direct parser call
        print(f"\n📖 Testing direct parser call...")
        if analyzer._parsers:
            parser = analyzer._parsers[0]
            print(f"   Parser: {type(parser).__name__}")
            log_file = analyzer._log_files[0]
            print(f"   File: {log_file}")
            
            # Direct parse call
            result = await parser.parse(log_file)
            print(f"   Parse result: {len(result.network_traces)} traces")
            
            # Check trace types
            if result.network_traces:
                first_trace = result.network_traces[0]
                print(f"   First trace type: {type(first_trace).__name__}")
                print(f"   Has request: {hasattr(first_trace, 'request') and first_trace.request is not None}")
                print(f"   Has response: {hasattr(first_trace, 'response') and first_trace.response is not None}")
                if hasattr(first_trace, 'request') and first_trace.request:
                    print(f"   Request URL: {first_trace.request.url}")
        
        # Test direct detector call
        print(f"\n🔍 Testing direct detector call...")
        if analyzer._detectors and analyzer._parsers:
            detector = analyzer._detectors[2]  # ProxyDetector is #3
            print(f"   Detector: {type(detector).__name__}")
            
            # Parse first to get traces
            parser = analyzer._parsers[0]
            parse_result = await parser.parse(analyzer._log_files[0])
            
            if parse_result.network_traces:
                from netstealth_analyzer.detectors.base import DetectionContext
                context = DetectionContext(
                    network_traces=parse_result.network_traces,
                    service_domains=[],
                    confidence_threshold=0.5
                )
                
                detect_result = await detector.detect(context)
                print(f"   Detection result: {len(detect_result.issues_found)} issues")
                
                for issue in detect_result.issues_found:
                    print(f"      - {issue.title}")
        
    except Exception as e:
        print(f"❌ Debug failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(debug_pipeline())
