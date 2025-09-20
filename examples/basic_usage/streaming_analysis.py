#!/usr/bin/env python3
"""
NetStealth Analyzer Example: Streaming Analysis

Description: Demonstrates real-time streaming analysis for processing large files
or continuous data streams. This example shows how to get results as they become
available without waiting for complete analysis.

Requirements:
- NetStealth Analyzer v2.0+
- Large log files or continuous data streams

Usage:
    python streaming_analysis.py
"""

import asyncio
import sys
import time
from pathlib import Path
from typing import AsyncIterator, Dict, Any
from netstealth_analyzer import NetStealthAnalyzer
from netstealth_analyzer.core.events import AnalysisEvent


class StreamingAnalysisDemo:
    """
    Demonstration of streaming analysis capabilities.
    
    Shows how to:
    - Process data streams in real-time
    - Handle results as they become available
    - Monitor progress continuously
    - Manage resources efficiently
    """
    
    def __init__(self):
        self.results_received = 0
        self.issues_found = 0
        self.start_time = None
        self.processed_data = []
    
    async def stream_large_file_analysis(self) -> None:
        """Demonstrate streaming analysis of a large file."""
        
        print("📡 Streaming Analysis - Large File Processing")
        print("=" * 45)
        
        # Use sample data - in practice this would be a large file
        sample_file = "../sample_data/sample_session.har"
        
        if not Path(sample_file).exists():
            print("❌ Sample file not found")
            print("💡 Make sure sample data exists in ../sample_data/")
            return
        
        file_size = Path(sample_file).stat().st_size / 1024
        print(f"📁 Streaming analysis of: {Path(sample_file).name} ({file_size:.1f} KB)")
        
        try:
            # Configure analyzer for streaming
            print("\n🔧 Configuring streaming analyzer...")
            
            analyzer = (NetStealthAnalyzer.create()
                        .with_logs(sample_file)
                        .for_service("example.com")
                        .enable_streaming()  # Enable streaming mode
                        .with_detectors("proxy", "browser", "network")
                        .track_progress(self._progress_callback)
                        .build())
            
            print("✅ Streaming analyzer configured")
            
            # Start streaming analysis
            print("\n📡 Starting streaming analysis...")
            self.start_time = time.time()
            
            async for update in analyzer.stream_analysis():
                await self._handle_stream_update(update)
                
                # Simulate some processing time
                await asyncio.sleep(0.1)
            
            # Final summary
            elapsed_time = time.time() - self.start_time
            print(f"\n✅ Streaming analysis completed!")
            print(f"   Total Updates: {self.results_received}")
            print(f"   Issues Found: {self.issues_found}")
            print(f"   Processing Time: {elapsed_time:.2f}s")
            print(f"   Avg Update Rate: {self.results_received / elapsed_time:.1f} updates/sec")
            
            # Cleanup
            await analyzer.shutdown()
            
        except Exception as e:
            print(f"❌ Streaming analysis failed: {e}")
            import traceback
            traceback.print_exc()
    
    async def stream_real_time_monitoring(self) -> None:
        """Demonstrate real-time monitoring capabilities."""
        
        print("\n🔄 Real-Time Monitoring Simulation")
        print("=" * 35)
        
        # Simulate continuous monitoring
        sample_files = [
            "../sample_data/sample_session.har",
            "../sample_data/sample_proxy.log"
        ]
        
        # Validate files
        for file in sample_files:
            if not Path(file).exists():
                print(f"❌ Missing file: {file}")
                return
        
        print(f"👁️  Monitoring {len(sample_files)} data sources...")
        
        try:
            # Create monitoring analyzer
            analyzer = (NetStealthAnalyzer.create()
                        .with_logs(*sample_files)
                        .for_service("example.com")
                        .enable_streaming()
                        .with_detectors("proxy", "browser", "network")
                        .build())
            
            print("🔄 Starting real-time monitoring...")
            
            # Monitor for a limited time (in practice this would run continuously)
            monitor_duration = 5.0  # seconds
            start_time = time.time()
            update_count = 0
            
            async for update in analyzer.stream_analysis():
                current_time = time.time()
                elapsed = current_time - start_time
                
                update_count += 1
                await self._handle_monitoring_update(update, elapsed)
                
                # Stop after monitor duration
                if elapsed >= monitor_duration:
                    break
                
                await asyncio.sleep(0.2)
            
            print(f"\n⏹️  Monitoring stopped after {monitor_duration}s")
            print(f"   Updates Processed: {update_count}")
            
            await analyzer.shutdown()
            
        except Exception as e:
            print(f"❌ Real-time monitoring failed: {e}")
            import traceback
            traceback.print_exc()
    
    async def _handle_stream_update(self, update: Dict[str, Any]) -> None:
        """Handle individual streaming updates."""
        
        self.results_received += 1
        update_type = update.get('type', 'unknown')
        
        # Process different types of updates
        if update_type == 'analysis_update':
            progress = update.get('progress', {})
            current = progress.get('current', 0)
            total = progress.get('total', 0)
            
            if total > 0:
                percentage = (current / total) * 100
                print(f"📊 Progress: {percentage:.1f}% ({current}/{total})")
            
        elif update_type == 'issue_found':
            issue = update.get('issue', {})
            severity = issue.get('severity', 'unknown')
            title = issue.get('title', 'Unknown Issue')
            
            severity_icons = {
                'critical': '💥', 'high': '🚨', 
                'medium': '⚠️', 'low': 'ℹ️'
            }
            icon = severity_icons.get(severity, '❓')
            
            self.issues_found += 1
            print(f"   {icon} Issue #{self.issues_found}: {title} ({severity})")
            
        elif update_type == 'trace_processed':
            trace_info = update.get('trace', {})
            trace_id = trace_info.get('trace_id', 'unknown')
            hops = trace_info.get('hops_count', 0)
            
            print(f"🔗 Processed trace {trace_id}: {hops} hops")
            
        elif update_type == 'detector_result':
            detector = update.get('detector_name', 'unknown')
            results_count = update.get('results_count', 0)
            
            print(f"🔍 {detector} detector: {results_count} findings")
        
        # Store update for later analysis
        self.processed_data.append({
            'timestamp': time.time(),
            'type': update_type,
            'data': update
        })
    
    async def _handle_monitoring_update(self, update: Dict[str, Any], elapsed_time: float) -> None:
        """Handle real-time monitoring updates."""
        
        update_type = update.get('type', 'unknown')
        timestamp = f"[{elapsed_time:.1f}s]"
        
        if update_type == 'analysis_update':
            print(f"{timestamp} 📡 Analysis update received")
            
        elif update_type == 'issue_found':
            issue = update.get('issue', {})
            severity = issue.get('severity', 'unknown')
            print(f"{timestamp} 🚨 New {severity} issue detected")
            
        elif update_type == 'system_status':
            status = update.get('status', 'unknown')
            print(f"{timestamp} ℹ️  System status: {status}")
            
        else:
            print(f"{timestamp} 📦 Update: {update_type}")
    
    def _progress_callback(self, current: int, total: int, message: str) -> None:
        """Progress callback for non-streaming updates."""
        
        if total > 0:
            percentage = (current / total) * 100
            print(f"⏳ Progress callback: {percentage:.1f}% - {message}")


async def demonstrate_streaming_features():
    """Demonstrate various streaming analysis features."""
    
    print("🌊 NetStealth Analyzer - Streaming Analysis Demo")
    print("=" * 48)
    
    demo = StreamingAnalysisDemo()
    
    # Feature 1: Large file streaming
    await demo.stream_large_file_analysis()
    
    # Feature 2: Real-time monitoring
    await demo.stream_real_time_monitoring()
    
    # Feature 3: Streaming benefits summary
    print("\n💡 Streaming Analysis Benefits:")
    print("   • Real-time results as data is processed")
    print("   • Memory-efficient processing of large files")
    print("   • Immediate issue detection and response")
    print("   • Continuous monitoring capabilities")
    print("   • Resource optimization for long-running analysis")
    
    return demo.processed_data


async def main():
    """Main function to run the streaming analysis example."""
    
    print("NetStealth Analyzer v2.0 - Python 3.13+")
    print("Starting streaming analysis example...\n")
    
    try:
        processed_data = await demonstrate_streaming_features()
        
        print(f"\n🎉 Streaming analysis demonstration completed!")
        print(f"   Stream Updates Processed: {len(processed_data)}")
        print(f"   Different Update Types: {len(set(item['type'] for item in processed_data))}")
        
        # Show update type distribution
        if processed_data:
            print(f"\n📈 Update Type Distribution:")
            type_counts = {}
            for item in processed_data:
                update_type = item['type']
                type_counts[update_type] = type_counts.get(update_type, 0) + 1
            
            for update_type, count in sorted(type_counts.items()):
                print(f"   • {update_type}: {count}")
        
        print(f"\n📚 What You Learned:")
        print(f"   • Real-time streaming analysis capabilities")
        print(f"   • Memory-efficient processing techniques")
        print(f"   • Continuous monitoring patterns")
        print(f"   • Progress tracking in streaming mode")
        print(f"   • Resource optimization strategies")
        
    except KeyboardInterrupt:
        print(f"\n⏹️  Streaming analysis interrupted by user")
        
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        
        print(f"\n💡 Troubleshooting Tips:")
        print(f"   - Ensure sample data exists in ../sample_data/")
        print(f"   - Check that NetStealth Analyzer is properly installed")
        print(f"   - Verify you're running from examples/basic_usage directory")
        print(f"   - Try the simple_analysis.py example first")


if __name__ == "__main__":
    asyncio.run(main())
