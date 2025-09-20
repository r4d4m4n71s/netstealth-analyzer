#!/usr/bin/env python3
"""
Debug script to trace the exact scoring calculation in the builder.
"""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from netstealth_analyzer.builder import AnalyzerBuilder


async def debug_builder_scoring():
    """Debug the exact scoring calculation in the builder."""
    print("🔍 Debugging Builder Scoring Calculation")
    print("=" * 60)
    
    # Build analyzer
    builder = AnalyzerBuilder()
    analyzer = (builder
                .with_log("examples/sample_data/sample_high_risk_session.har")
                .for_service("example.com")
                .build())
    
    # Monkey patch the scoring calculation to add debug output
    original_direct_analysis = analyzer._direct_analysis
    
    async def debug_direct_analysis():
        """Debug version of _direct_analysis with scoring trace."""
        from netstealth_analyzer.models.results import AnalysisSummary
        from netstealth_analyzer.detectors.base import DetectionContext
        from netstealth_analyzer.models.enums import AnalysisStatus
        
        # Create execution context
        from netstealth_analyzer.models.results import ExecutionContext
        execution_context = ExecutionContext(
            analyzer_version="2.0.0",
            input_files=analyzer._log_files,
            input_formats=list(analyzer._log_formats.values())
        )
        
        try:
            # Step 1: Parse log files
            all_network_traces = []
            
            for log_file in analyzer._log_files:
                log_format = analyzer._log_formats.get(log_file)
                
                # Find appropriate parser
                parser = None
                for p in analyzer._parsers:
                    if hasattr(p, 'supported_format') and p.supported_format == log_format:
                        parser = p
                        break
                
                if parser:
                    print(f"Parsing {log_file} with {type(parser).__name__}")
                    parse_result = await parser.parse(log_file)
                    all_network_traces.extend(parse_result.network_traces)
                    print(f"Parsed {len(parse_result.network_traces)} traces from {log_file}")
            
            print(f"Total network traces: {len(all_network_traces)}")
            
            # Step 2: Run detectors
            all_issues = []
            
            if all_network_traces:
                context = DetectionContext(
                    network_traces=all_network_traces,
                    service_domains=[analyzer._config.target_service] if analyzer._config.target_service else [],
                    confidence_threshold=0.5
                )
                
                for detector in analyzer._detectors:
                    print(f"Running {type(detector).__name__}")
                    detection_result = await detector.detect(context)
                    all_issues.extend(detection_result.issues_found)
                    print(f"Found {len(detection_result.issues_found)} issues with {type(detector).__name__}")
            
            print(f"Total issues found: {len(all_issues)}")
            
            # Step 3: Calculate score with detailed debugging
            print(f"\n🧮 DETAILED SCORING CALCULATION:")
            overall_score = 100
            print(f"Starting score: {overall_score}")
            
            for i, issue in enumerate(all_issues):
                # Handle both enum and string severity values
                if hasattr(issue.severity, 'value'):
                    severity = issue.severity.value.lower()
                    print(f"Issue {i+1}: severity.value = '{issue.severity.value}' -> '{severity}'")
                else:
                    severity = str(issue.severity).lower()
                    print(f"Issue {i+1}: str(severity) = '{issue.severity}' -> '{severity}'")
                
                old_score = overall_score
                
                if severity == 'critical':
                    overall_score -= 3
                    print(f"  Critical: {old_score} - 3 = {overall_score}")
                elif severity == 'high':
                    overall_score -= 2
                    print(f"  High: {old_score} - 2 = {overall_score}")
                elif severity == 'medium':
                    overall_score -= 1
                    print(f"  Medium: {old_score} - 1 = {overall_score}")
                elif severity == 'low':
                    overall_score -= 0.5
                    print(f"  Low: {old_score} - 0.5 = {overall_score}")
                else:
                    print(f"  Unknown severity '{severity}': no deduction")
                
                # Stop after first 10 issues to avoid spam
                if i >= 9:
                    print(f"  ... (stopping debug after 10 issues, {len(all_issues) - 10} remaining)")
                    # Continue calculation without debug output
                    for remaining_issue in all_issues[10:]:
                        if hasattr(remaining_issue.severity, 'value'):
                            remaining_severity = remaining_issue.severity.value.lower()
                        else:
                            remaining_severity = str(remaining_issue.severity).lower()
                        
                        if remaining_severity == 'critical':
                            overall_score -= 3
                        elif remaining_severity == 'high':
                            overall_score -= 2
                        elif remaining_severity == 'medium':
                            overall_score -= 1
                        elif remaining_severity == 'low':
                            overall_score -= 0.5
                    break
            
            overall_score = max(0, int(overall_score))
            print(f"\nFinal calculated score: {overall_score}")
            
            # Step 4: Create result
            summary = AnalysisSummary(
                status=AnalysisStatus.SUCCESS,
                overall_score=overall_score,
                analysis_duration_ms=100
            )
            
            from netstealth_analyzer.models.results import AnalysisResult
            result = AnalysisResult(
                summary=summary,
                execution_context=execution_context
            )
            
            # Add issues to result
            for issue in all_issues:
                result.add_issue(issue)
            
            # Add network traces to result
            for trace in all_network_traces:
                result.add_network_trace(trace)
            
            result.finalize_result()
            
            print(f"Result summary score: {result.summary.overall_score}")
            
            return result
            
        except Exception as e:
            print(f"Analysis failed: {e}")
            import traceback
            traceback.print_exc()
            
            # Create failed result
            summary = AnalysisSummary(
                status=AnalysisStatus.FAILED,
                overall_score=0
            )
            
            from netstealth_analyzer.models.results import AnalysisResult
            result = AnalysisResult(
                summary=summary,
                execution_context=execution_context
            )
            
            result.finalize_result()
            return result
    
    # Replace the method
    analyzer._direct_analysis = debug_direct_analysis
    
    # Run analysis
    print("\n⚙️ Running analysis with debug scoring...")
    result = await analyzer.analyze()
    
    print(f"\n📊 Final Results:")
    print(f"   Overall Score: {result.summary.overall_score}/100")
    print(f"   Total Issues: {len(result.issues)}")


if __name__ == "__main__":
    asyncio.run(debug_builder_scoring())
