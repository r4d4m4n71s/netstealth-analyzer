#!/usr/bin/env python3
"""
Simple debug script with print statements to see what's happening.
"""

import asyncio
from pathlib import Path

from src.netstealth_analyzer.builder import AnalyzerBuilder


async def debug_simple_analysis():
    """Debug with print statements."""
    print("🔍 Simple debug analysis...")
    
    # Build analyzer
    har_file = Path("examples/sample_data/sample_high_risk_session.har")
    
    print(f"\n🏗️ Building analyzer...")
    builder = AnalyzerBuilder()
    analyzer = builder.with_log(har_file).for_service("target-service.com").build()
    
    print(f"   Built analyzer with:")
    print(f"   - {len(analyzer._parsers)} parsers")
    print(f"   - {len(analyzer._detectors)} detectors")
    print(f"   - {len(analyzer._log_files)} log files")
    
    # Manually call _direct_analysis with debug prints
    print(f"\n🔍 Calling _direct_analysis manually...")
    
    try:
        # Step 1: Check log files
        print(f"   Log files: {analyzer._log_files}")
        print(f"   Log formats: {analyzer._log_formats}")
        
        # Step 2: Check parsers
        print(f"   Parsers: {[type(p).__name__ for p in analyzer._parsers]}")
        
        # Step 3: Try parsing manually
        all_network_traces = []
        
        for log_file in analyzer._log_files:
            log_format = analyzer._log_formats.get(log_file)
            print(f"   Processing {log_file} with format {log_format}")
            
            # Find parser
            parser = None
            for p in analyzer._parsers:
                print(f"      Checking parser {type(p).__name__}")
                if hasattr(p, 'supported_format'):
                    print(f"         Supports: {p.supported_format}")
                    if p.supported_format == log_format:
                        parser = p
                        print(f"         ✅ Match found!")
                        break
                else:
                    print(f"         ❌ No supported_format")
            
            if parser:
                print(f"      Using parser: {type(parser).__name__}")
                try:
                    parse_result = await parser.parse(log_file)
                    print(f"      ✅ Parse successful: {len(parse_result.network_traces)} traces")
                    all_network_traces.extend(parse_result.network_traces)
                except Exception as e:
                    print(f"      ❌ Parse failed: {e}")
                    import traceback
                    traceback.print_exc()
            else:
                print(f"      ❌ No parser found")
        
        print(f"\n   Total traces collected: {len(all_network_traces)}")
        
        # Step 4: Test detectors
        if all_network_traces:
            from src.netstealth_analyzer.detectors.base import DetectionContext
            
            context = DetectionContext(
                network_traces=all_network_traces,
                service_domains=["target-service.com"],
                confidence_threshold=0.5
            )
            
            all_issues = []
            for detector in analyzer._detectors:
                print(f"   Testing {type(detector).__name__}...")
                try:
                    detection_result = await detector.detect(context)
                    print(f"      ✅ Found {len(detection_result.issues_found)} issues")
                    all_issues.extend(detection_result.issues_found)
                except Exception as e:
                    print(f"      ❌ Detection failed: {e}")
                    import traceback
                    traceback.print_exc()
            
            print(f"\n   Total issues found: {len(all_issues)}")
            
            for i, issue in enumerate(all_issues):
                severity = issue.severity.value if hasattr(issue.severity, 'value') else str(issue.severity)
                print(f"      Issue {i+1}: [{severity.upper()}] {issue.title}")
        
        # Now test the actual analyzer.analyze() method
        print(f"\n🧪 Testing analyzer.analyze()...")
        result = await analyzer.analyze()
        print(f"   Result score: {result.summary.overall_score}")
        print(f"   Result issues: {len(result.issues)}")
        print(f"   Result traces: {len(result.network_traces)}")
        print(f"   Result status: {result.summary.status}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(debug_simple_analysis())
