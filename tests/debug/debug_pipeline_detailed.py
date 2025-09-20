#!/usr/bin/env python3

import asyncio
import sys
import os
import logging

# Add the src directory to Python path
sys.path.insert(0, 'src')

# Configure detailed logging
logging.basicConfig(level=logging.DEBUG, 
                   format='%(levelname)s:%(name)s:%(message)s')
logger = logging.getLogger(__name__)

from netstealth_analyzer import NetStealthAnalyzer

async def debug_pipeline_detailed():
    print("🔬 Debug: Detailed pipeline execution trace...")
    
    try:
        # Create analyzer the same way the test does
        print("Building analyzer...")
        analyzer = (NetStealthAnalyzer.create()
                    .with_log("examples/sample_data/sample_high_risk_session.har")
                    .build())
        
        # Initialize 
        print(f"\nInitializing analyzer...")
        await analyzer.initialize()
        
        # Get pipeline
        pipeline = analyzer._pipeline
        print(f"\nPipeline stages: {list(pipeline._stages.keys())}")
        
        # Debug: manually trace pipeline execution like analyzer.analyze() does
        print(f"\n🔄 Manually running pipeline execution...")
        
        from netstealth_analyzer.core.interfaces import ProcessingContext
        
        # Create processing context exactly like analyzer does
        processing_context = ProcessingContext(
            file_path=analyzer._log_files[0] if analyzer._log_files else None
        )
        
        print(f"ProcessingContext file_path: {processing_context.file_path}")
        
        # Prepare input data exactly like analyzer does
        input_data = {
            'log_files': analyzer._log_files,
            'log_formats': analyzer._log_formats,
            'config': analyzer._config.model_dump(),
        }
        
        print(f"Input data keys: {list(input_data.keys())}")
        print(f"Log files: {input_data['log_files']}")
        
        # Execute pipeline manually
        print(f"\n🚀 Executing pipeline...")
        pipeline_result = await pipeline.execute(
            input_data=input_data,
            context=processing_context
        )
        
        print(f"\n📊 Pipeline Results:")
        print(f"   Success: {pipeline_result.success}")
        if pipeline_result.error:
            print(f"   Error: {pipeline_result.error}")
        
        if pipeline_result.data:
            print(f"   Data keys: {list(pipeline_result.data.keys())}")
            
            # Look for parser results
            for key, value in pipeline_result.data.items():
                if key.startswith('parser_'):
                    print(f"   {key}: {type(value)}")
                    if hasattr(value, 'network_traces'):
                        print(f"      network_traces: {len(value.network_traces)}")
                elif key.startswith('detector_'):
                    print(f"   {key}: {type(value)}")
                    if hasattr(value, 'issues_found'):
                        print(f"      issues_found: {len(value.issues_found)}")
                        for issue in value.issues_found[:3]:  # Show first 3
                            print(f"         - {issue.title}")
        else:
            print(f"   No data returned!")
        
    except Exception as e:
        print(f"❌ Debug failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(debug_pipeline_detailed())
