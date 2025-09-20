#!/usr/bin/env python3
"""Debug test to find the exact failure point in analysis pipeline."""

import sys
import os
import asyncio

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

async def test_analysis_step_by_step():
    """Test each step of analysis individually."""
    
    print("🧪 Step-by-step Analysis Debug")
    print("=" * 50)
    
    try:
        print("📦 Step 1: Testing imports...")
        from netstealth_analyzer import NetStealthAnalyzer
        from netstealth_analyzer.models.results import AnalysisSummary, AnalysisResult, ExecutionContext
        from netstealth_analyzer.detectors.base import DetectionContext
        from netstealth_analyzer.models.enums import AnalysisStatus
        print("✅ All imports successful")
        
        print("\n📦 Step 2: Testing builder...")
        builder = NetStealthAnalyzer.create()
        builder = builder.with_logs("examples/sample_data/sample_high_risk_session.har")
        builder = builder.with_detectors("browser")
        analyzer = builder.build()
        print("✅ Builder and analyzer creation successful")
        
        print("\n📦 Step 3: Testing direct method access...")
        print(f"   Has _direct_analysis: {hasattr(analyzer, '_direct_analysis')}")
        print(f"   Has _log_files: {hasattr(analyzer, '_log_files')} (count: {len(analyzer._log_files)})")
        print(f"   Has _log_formats: {hasattr(analyzer, '_log_formats')} (count: {len(analyzer._log_formats)})")
        print(f"   Has _parsers: {hasattr(analyzer, '_parsers')} (count: {len(analyzer._parsers)})")
        print(f"   Has _detectors: {hasattr(analyzer, '_detectors')} (count: {len(analyzer._detectors)})")
        
        print("\n📦 Step 4: Testing ExecutionContext creation...")
        execution_context = ExecutionContext(
            analyzer_version="2.0.0",
            input_files=analyzer._log_files,
            input_formats=list(analyzer._log_formats.values())
        )
        print(f"✅ ExecutionContext created: {execution_context.execution_id}")
        
        print("\n📦 Step 5: Testing direct _direct_analysis call...")
        result = await analyzer._direct_analysis()
        print(f"✅ _direct_analysis returned: {type(result).__name__}")
        print(f"   Issues found: {len(result.issues)}")
        print(f"   Overall score: {result.summary.overall_score}")
        
    except Exception as e:
        print(f"❌ Error at step: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_analysis_step_by_step())
