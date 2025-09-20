#!/usr/bin/env python3
"""
Debug script to test the direct analysis method step by step.
"""

import asyncio
from pathlib import Path

from src.netstealth_analyzer.builder import AnalyzerBuilder
from src.netstealth_analyzer.models.enums import LogFormat


async def debug_direct_analysis():
    """Debug the direct analysis method step by step."""
    print("🔍 Debugging direct analysis method...")
    
    # Build analyzer using the same method as test_high_risk_verification.py
    har_file = Path("examples/sample_data/sample_high_risk_session.har")
    
    print(f"\n🏗️ Building analyzer...")
    builder = AnalyzerBuilder()
    analyzer = builder.with_log(har_file).for_service("target-service.com").build()
    
    print(f"   Built analyzer with:")
    print(f"   - {len(analyzer._parsers)} parsers")
    print(f"   - {len(analyzer._detectors)} detectors")
    print(f"   - {len(analyzer._log_files)} log files")
    print(f"   - Log formats: {analyzer._log_formats}")
    
    # Debug the direct analysis step by step
    print(f"\n🔍 Step-by-step direct analysis debug...")
    
    # Step 1: Check log files and formats
    print(f"\n📁 Step 1: Log files and formats")
    for log_file in analyzer._log_files:
        log_format = analyzer._log_formats.get(log_file)
        print(f"   File: {log_file}")
        print(f"   Format: {log_format}")
        print(f"   Exists: {log_file.exists()}")
    
    # Step 2: Check parsers
    print(f"\n🔧 Step 2: Available parsers")
    for i, parser in enumerate(analyzer._parsers):
        print(f"   Parser {i+1}: {type(parser).__name__}")
        if hasattr(parser, 'supported_format'):
            print(f"      Supported format: {parser.supported_format}")
        else:
            print(f"      ❌ No supported_format attribute!")
    
    # Step 3: Test parser matching
    print(f"\n🔍 Step 3: Parser matching test")
    for log_file in analyzer._log_files:
        log_format = analyzer._log_formats.get(log_file)
        print(f"   Looking for parser for {log_file} (format: {log_format})")
        
        parser = None
        for p in analyzer._parsers:
            print(f"      Checking {type(p).__name__}...")
            if hasattr(p, 'supported_format'):
                print(f"         Has supported_format: {p.supported_format}")
                print(f"         Match check: {p.supported_format == log_format}")
                if p.supported_format == log_format:
                    parser = p
                    break
            else:
                print(f"         ❌ No supported_format attribute")
        
        if parser:
            print(f"   ✅ Found parser: {type(parser).__name__}")
            
            # Test parsing
            print(f"   🧪 Testing parsing...")
            try:
                parse_result = await parser.parse(log_file)
                print(f"      ✅ Parsing successful!")
                print(f"      Network traces: {len(parse_result.network_traces)}")
                
                for i, trace in enumerate(parse_result.network_traces):
                    print(f"      Trace {i+1}: {trace.protocol}, HTTP data: {trace.is_http()}")
                    
            except Exception as e:
                print(f"      ❌ Parsing failed: {e}")
                import traceback
                traceback.print_exc()
        else:
            print(f"   ❌ No parser found!")
    
    print(f"\n🎯 Summary:")
    print(f"   - Log files: {len(analyzer._log_files)}")
    print(f"   - Parsers: {len(analyzer._parsers)}")
    print(f"   - Detectors: {len(analyzer._detectors)}")


if __name__ == "__main__":
    asyncio.run(debug_direct_analysis())
