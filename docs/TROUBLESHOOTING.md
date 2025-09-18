# 🔧 NetStealth Analyzer v2.0 - Troubleshooting Guide

**Common Issues and Solutions**

This guide helps you diagnose and resolve common issues when using NetStealth Analyzer.

---

## 📋 Table of Contents

1. [Quick Diagnostics](#quick-diagnostics)
2. [Installation Issues](#installation-issues)
3. [Configuration Problems](#configuration-problems)
4. [File Parsing Issues](#file-parsing-issues)
5. [Analysis Problems](#analysis-problems)
6. [Performance Issues](#performance-issues)
7. [Memory and Resource Issues](#memory-and-resource-issues)
8. [Output and Reporting Issues](#output-and-reporting-issues)
9. [Event and Progress Issues](#event-and-progress-issues)
10. [Debug Mode and Logging](#debug-mode-and-logging)

---

## 🩺 Quick Diagnostics

### System Check

Run this diagnostic script to check your environment:

```python
import asyncio
import sys
import platform
import psutil
from pathlib import Path

async def system_diagnostics():
    """Run comprehensive system diagnostics."""
    
    print("🔍 NetStealth Analyzer System Diagnostics")
    print("=" * 50)
    
    # Python version
    print(f"Python Version: {sys.version}")
    print(f"Platform: {platform.platform()}")
    
    # Memory info
    memory = psutil.virtual_memory()
    print(f"Available Memory: {memory.available / (1024**3):.1f} GB")
    print(f"Total Memory: {memory.total / (1024**3):.1f} GB")
    
    # Disk space
    disk = psutil.disk_usage('.')
    print(f"Available Disk: {disk.free / (1024**3):.1f} GB")
    
    # Test import
    try:
        from netstealth_analyzer import NetStealthAnalyzer
        print("✅ NetStealth Analyzer import successful")
        
        # Test basic functionality
        analyzer = NetStealthAnalyzer.create()
        print("✅ Analyzer creation successful")
        
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Basic functionality test failed: {e}")
        return False
    
    print("\n✅ System diagnostics completed successfully")
    return True

# Run diagnostics
asyncio.run(system_diagnostics())
```

### Quick Health Check

```python
async def quick_health_check():
    """Quick health check for NetStealth Analyzer."""
    
    try:
        from netstealth_analyzer import NetStealthAnalyzer
        
        # Create minimal analyzer
        analyzer = (NetStealthAnalyzer.create()
            .with_logs("test.har")  # Non-existent file for testing
            .build())
        
        print("✅ Analyzer creation: OK")
        
        # Test configuration validation
        try:
            analyzer.validate()
            print("❌ Validation should have failed for non-existent file")
        except Exception:
            print("✅ Configuration validation: OK")
        
        return True
        
    except Exception as e:
        print(f"❌ Health check failed: {e}")
        return False

asyncio.run(quick_health_check())
```

---

## 📦 Installation Issues

### Issue: "ModuleNotFoundError: No module named 'netstealth_analyzer'"

**Cause**: Package not installed or not in Python path

**Solutions**:

1. **Verify Installation**:
```bash
# Check if installed
pip list | grep netstealth

# Or with poetry
poetry show netstealth-analyzer
```

2. **Reinstall Package**:
```bash
# With pip
pip uninstall netstealth-analyzer
pip install -e .

# With poetry
poetry install --force
```

3. **Check Python Path**:
```python
import sys
print("Python path:")
for path in sys.path:
    print(f"  {path}")
```

### Issue: "ImportError: cannot import name 'NetStealthAnalyzer'"

**Cause**: Partial installation or corrupted package

**Solutions**:

1. **Clean Reinstall**:
```bash
# Remove package completely
pip uninstall netstealth-analyzer
rm -rf build/ dist/ *.egg-info/

# Reinstall
pip install -e .
```

2. **Check Package Structure**:
```python
import netstealth_analyzer
print(f"Package location: {netstealth_analyzer.__file__}")
print(f"Package contents: {dir(netstealth_analyzer)}")
```

### Issue: "Python version compatibility error"

**Cause**: Using unsupported Python version

**Solutions**:

1. **Check Python Version**:
```bash
python --version
# Should be 3.11+ (3.13+ recommended)
```

2. **Use Correct Python Version**:
```bash
# Install Python 3.13
pyenv install 3.13.0
pyenv local 3.13.0

# Or use conda
conda create -n netstealth python=3.13
conda activate netstealth
```

---

## ⚙️ Configuration Problems

### Issue: "No log files configured for analysis"

**Cause**: Analyzer built without log files

**Solution**:
```python
# ❌ Wrong
analyzer = NetStealthAnalyzer.create().build()

# ✅ Correct
analyzer = (NetStealthAnalyzer.create()
    .with_logs("session.har")
    .build())
```

### Issue: "Configuration validation failed"

**Cause**: Invalid configuration parameters

**Debugging**:
```python
def debug_configuration():
    """Debug configuration step by step."""
    
    try:
        analyzer = NetStealthAnalyzer.create()
        print("✅ Analyzer created")
        
        analyzer = analyzer.with_logs("session.har")
        print("✅ Log file added")
        
        analyzer = analyzer.for_service("example.com")
        print("✅ Service configured")
        
        analyzer = analyzer.validate()
        print("✅ Configuration validated")
        
        built_analyzer = analyzer.build()
        print("✅ Analyzer built successfully")
        
        return built_analyzer
        
    except Exception as e:
        print(f"❌ Configuration failed at: {e}")
        return None
```

### Issue: "Invalid detector name"

**Cause**: Using non-existent detector name

**Solution**:
```python
# Check available detectors
from netstealth_analyzer.detectors import get_available_detectors
available = get_available_detectors()
print(f"Available detectors: {available}")

# Use correct detector names
analyzer = (NetStealthAnalyzer.create()
    .with_detectors(["proxy", "browser", "network", "tls"])  # Valid names
    .build())
```

---

## 📄 File Parsing Issues

### Issue: "Failed to parse log file"

**Cause**: Incorrect file format or corrupted file

**Debugging**:
```python
def debug_file_parsing(file_path):
    """Debug file parsing issues."""
    
    from pathlib import Path
    import json
    
    file_path = Path(file_path)
    
    # Check file exists
    if not file_path.exists():
        print(f"❌ File does not exist: {file_path}")
        return False
    
    # Check file size
    size_mb = file_path.stat().st_size / (1024 * 1024)
    print(f"📁 File size: {size_mb:.1f} MB")
    
    # Check file format
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            first_line = f.readline().strip()
            print(f"📝 First line: {first_line[:100]}...")
            
            # Try to parse as JSON (for HAR files)
            f.seek(0)
            data = json.load(f)
            print("✅ Valid JSON format")
            
            # Check HAR structure
            if 'log' in data:
                print("✅ HAR format detected")
                entries = len(data['log'].get('entries', []))
                print(f"📊 HAR entries: {entries}")
            else:
                print("⚠️ Not a HAR file")
                
    except json.JSONDecodeError as e:
        print(f"❌ JSON parsing failed: {e}")
        print("💡 File might be in different format (mitmproxy, browser log)")
    except UnicodeDecodeError as e:
        print(f"❌ Encoding error: {e}")
        print("💡 Try different encoding or check file corruption")
    except Exception as e:
        print(f"❌ File parsing error: {e}")
    
    return True

# Usage
debug_file_parsing("session.har")
```

### Issue: "Empty or invalid HAR file"

**Cause**: HAR file has no entries or invalid structure

**Solution**:
```python
def validate_har_file(file_path):
    """Validate HAR file structure."""
    
    import json
    
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        # Check HAR structure
        if 'log' not in data:
            print("❌ Missing 'log' field in HAR file")
            return False
        
        log = data['log']
        
        # Check entries
        entries = log.get('entries', [])
        if not entries:
            print("❌ HAR file has no entries")
            return False
        
        print(f"✅ HAR file valid with {len(entries)} entries")
        
        # Check entry structure
        first_entry = entries[0]
        required_fields = ['request', 'response', 'startedDateTime']
        
        for field in required_fields:
            if field not in first_entry:
                print(f"⚠️ Missing field in entry: {field}")
        
        return True
        
    except Exception as e:
        print(f"❌ HAR validation failed: {e}")
        return False

# Usage
validate_har_file("session.har")
```

### Issue: "Unsupported log format"

**Cause**: File format not recognized

**Solution**:
```python
from netstealth_analyzer.models.enums import LogFormat

# Specify format explicitly
analyzer = (NetStealthAnalyzer.create()
    .with_logs([
        ("session.har", LogFormat.HAR),
        ("proxy.log", LogFormat.MITMPROXY),
        ("browser.log", LogFormat.BROWSER_CONSOLE)
    ])
    .build())
```

---

## 🔍 Analysis Problems

### Issue: "Analysis timeout"

**Cause**: Analysis taking too long for large files

**Solutions**:

1. **Increase Timeout**:
```python
analyzer = (NetStealthAnalyzer.create()
    .with_logs("large_file.har")
    .timeout(1800)  # 30 minutes
    .build())
```

2. **Use Streaming Analysis**:
```python
async def streaming_analysis():
    analyzer = (NetStealthAnalyzer.create()
        .with_logs("large_file.har")
        .enable_streaming()
        .build())
    
    async for update in analyzer.stream_analysis():
        print(f"Progress: {update.get('percentage', 0):.1f}%")
```

3. **Reduce Analysis Scope**:
```python
analyzer = (NetStealthAnalyzer.create()
    .with_logs("large_file.har")
    .with_detectors(["proxy"])  # Only essential detectors
    .quick_mode()  # Fast analysis mode
    .build())
```

### Issue: "No issues detected when expected"

**Cause**: Configuration or detection thresholds too strict

**Debugging**:
```python
async def debug_detection():
    """Debug why no issues are detected."""
    
    # Lower confidence threshold
    analyzer = (NetStealthAnalyzer.create()
        .with_logs("session.har")
        .for_service("example.com")
        .build())
    
    result = await analyzer.analyze()
    
    print(f"Issues found: {len(result.issues)}")
    print(f"Network traces: {len(result.network_traces)}")
    
    # Check if detectors ran
    for detector_name in ["proxy", "browser", "network"]:
        detector_issues = [i for i in result.issues 
                          if detector_name in i.metadata.get('detector', '').lower()]
        print(f"{detector_name} detector issues: {len(detector_issues)}")
    
    # Check raw data
    if result.network_traces:
        trace = result.network_traces[0]
        print(f"Sample trace: {trace.trace_id}")
        print(f"Trace metadata keys: {list(trace.metadata.keys())}")

asyncio.run(debug_detection())
```

### Issue: "Analysis fails with unclear error"

**Cause**: Internal error during analysis

**Debugging**:
```python
import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('netstealth_analyzer')
logger.setLevel(logging.DEBUG)

async def debug_analysis():
    """Run analysis with full debugging."""
    
    try:
        analyzer = (NetStealthAnalyzer.create()
            .with_logs("session.har")
            .for_service("example.com")
            .build())
        
        result = await analyzer.analyze()
        print("✅ Analysis completed successfully")
        return result
        
    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return None

asyncio.run(debug_analysis())
```

---

## ⚡ Performance Issues

### Issue: "Analysis is very slow"

**Cause**: Large files or inefficient configuration

**Solutions**:

1. **Enable Parallel Processing**:
```python
analyzer = (NetStealthAnalyzer.create()
    .with_logs("large_file.har")
    .max_concurrent_parsers(8)
    .max_concurrent_detectors(4)
    .build())
```

2. **Use Streaming for Large Files**:
```python
analyzer = (NetStealthAnalyzer.create()
    .with_logs("large_file.har")
    .streaming_threshold(100)  # Stream files >100MB
    .enable_streaming()
    .build())
```

3. **Optimize Detector Selection**:
```python
# Only use necessary detectors
analyzer = (NetStealthAnalyzer.create()
    .with_logs("file.har")
    .with_detectors(["proxy", "browser"])  # Skip network and TLS
    .build())
```

### Issue: "High CPU usage"

**Cause**: Too many concurrent operations

**Solution**:
```python
import psutil

# Limit concurrency based on CPU cores
cpu_count = psutil.cpu_count()
max_parsers = max(2, cpu_count // 2)

analyzer = (NetStealthAnalyzer.create()
    .with_logs("file.har")
    .max_concurrent_parsers(max_parsers)
    .max_concurrent_detectors(2)
    .build())
```

### Issue: "Disk I/O bottleneck"

**Cause**: Reading large files from slow storage

**Solutions**:

1. **Use SSD Storage**:
```bash
# Move files to faster storage
mv large_files/ /path/to/ssd/
```

2. **Increase Buffer Size**:
```python
analyzer = (NetStealthAnalyzer.create()
    .with_logs("large_file.har")
    .chunk_size(8192)  # Larger chunks
    .build())
```

---

## 💾 Memory and Resource Issues

### Issue: "Out of memory error"

**Cause**: Large files consuming too much memory

**Solutions**:

1. **Set Memory Limit**:
```python
analyzer = (NetStealthAnalyzer.create()
    .with_logs("large_file.har")
    .memory_limit(512)  # 512MB limit
    .build())
```

2. **Use Streaming Analysis**:
```python
async def memory_efficient_analysis():
    analyzer = (NetStealthAnalyzer.create()
        .with_logs("large_file.har")
        .enable_streaming()
        .build())
    
    # Process results immediately to free memory
    async for update in analyzer.stream_analysis():
        if update['type'] == 'issue_found':
            process_issue_immediately(update)
            # Don't store in memory
```

3. **Process Files Individually**:
```python
async def process_files_individually(file_list):
    """Process large files one at a time."""
    
    all_issues = []
    
    for file_path in file_list:
        analyzer = (NetStealthAnalyzer.create()
            .with_logs(file_path)
            .build())
        
        result = await analyzer.analyze()
        all_issues.extend(result.issues)
        
        # Clean up
        await analyzer.shutdown()
        del analyzer, result
    
    return all_issues
```

### Issue: "System becomes unresponsive"

**Cause**: Resource exhaustion

**Solution**:
```python
import psutil

def get_safe_resource_limits():
    """Calculate safe resource limits."""
    
    # Memory
    memory = psutil.virtual_memory()
    safe_memory_mb = int(memory.available * 0.3 / (1024 * 1024))  # Use 30% of available
    
    # CPU
    cpu_count = psutil.cpu_count()
    safe_cpu_cores = max(1, cpu_count - 2)  # Leave 2 cores free
    
    return {
        'memory_limit': safe_memory_mb,
        'max_concurrent_parsers': safe_cpu_cores,
        'max_concurrent_detectors': max(1, safe_cpu_cores // 2)
    }

# Apply safe limits
limits = get_safe_resource_limits()
analyzer = (NetStealthAnalyzer.create()
    .with_logs("file.har")
    .memory_limit(limits['memory_limit'])
    .max_concurrent_parsers(limits['max_concurrent_parsers'])
    .max_concurrent_detectors(limits['max_concurrent_detectors'])
    .build())
```

---

## 📊 Output and Reporting Issues

### Issue: "Report generation fails"

**Cause**: Output directory issues or format problems

**Solutions**:

1. **Check Output Directory**:
```python
from pathlib import Path

def ensure_output_directory(output_dir):
    """Ensure output directory exists and is writable."""
    
    output_path = Path(output_dir)
    
    try:
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Test write permissions
        test_file = output_path / "test_write.tmp"
        test_file.write_text("test")
        test_file.unlink()
        
        print(f"✅ Output directory ready: {output_path}")
        return True
        
    except PermissionError:
        print(f"❌ No write permission: {output_path}")
        return False
    except Exception as e:
        print(f"❌ Output directory error: {e}")
        return False

# Usage
ensure_output_directory("./reports")
```

2. **Handle Report Generation Errors**:
```python
async def safe_report_generation(analyzer, result):
    """Generate reports with error handling."""
    
    formats = ["json", "html", "markdown"]
    
    for format_type in formats:
        try:
            output_file = f"report.{format_type}"
            await analyzer.report(result, format=format_type, output=output_file)
            print(f"✅ Generated {format_type} report: {output_file}")
            
        except Exception as e:
            print(f"❌ Failed to generate {format_type} report: {e}")
            continue
```

### Issue: "HTML report not displaying correctly"

**Cause**: Missing dependencies or browser compatibility

**Solutions**:

1. **Check HTML Report**:
```python
def validate_html_report(html_file):
    """Validate HTML report structure."""
    
    from pathlib import Path
    
    html_path = Path(html_file)
    
    if not html_path.exists():
        print(f"❌ HTML report not found: {html_file}")
        return False
    
    content = html_path.read_text()
    
    # Check for required elements
    required_elements = [
        '<html', '<head>', '<body>',
        'NetStealth', 'Analysis Report'
    ]
    
    for element in required_elements:
        if element not in content:
            print(f"⚠️ Missing element in HTML: {element}")
    
    print(f"✅ HTML report validated: {html_file}")
    return True

# Usage
validate_html_report("report.html")
```

---

## 📡 Event and Progress Issues

### Issue: "Progress callback not working"

**Cause**: Incorrect callback function or event handling

**Solution**:
```python
def debug_progress_tracking():
    """Debug progress tracking issues."""
    
    progress_calls = []
    
    def progress_callback(current, total, message):
        progress_calls.append((current, total, message))
        print(f"Progress: {current}/{total} - {message}")
    
    analyzer = (NetStealthAnalyzer.create()
        .with_logs("session.har")
        .track_progress(progress_callback)
        .build())
    
    # After analysis, check if callback was called
    print(f"Progress callback called {len(progress_calls)} times")
    
    return analyzer
```

### Issue: "Event handlers not triggered"

**Cause**: Incorrect event registration or async issues

**Solution**:
```python
from netstealth_analyzer.core.events import AnalysisEvent

async def debug_event_handling():
    """Debug event handling issues."""
    
    events_received = []
    
    async def event_handler(event, data):
        events_received.append((event, data))
        print(f"Event received: {event}")
    
    analyzer = (NetStealthAnalyzer.create()
        .with_logs("session.har")
        .on_event(AnalysisEvent.ANALYSIS_STARTED, event_handler)
        .on_event(AnalysisEvent.ISSUE_FOUND, event_handler)
        .on_event(AnalysisEvent.ANALYSIS_COMPLETED, event_handler)
        .build())
    
    result = await analyzer.analyze()
    
    print(f"Events received: {len(events_received)}")
    for event, data in events_received:
        print(f"  - {event}")
    
    return result

asyncio.run(debug_event_handling())
```

---

## 🐛 Debug Mode and Logging

### Enable Debug Logging

```python
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('netstealth_debug.log'),
        logging.StreamHandler()
    ]
)

# Set specific logger levels
logging.getLogger('netstealth_analyzer').setLevel(logging.DEBUG)
logging.getLogger('netstealth_analyzer.parsers').setLevel(logging.DEBUG)
logging.getLogger('netstealth_analyzer.detectors').setLevel(logging.DEBUG)
```

### Comprehensive Debug Session

```python
async def comprehensive_debug_session():
    """Run comprehensive debugging session."""
    
    print("🐛 Starting comprehensive debug session")
    print("=" * 50)
    
    # System info
    await system_diagnostics()
    
    # Configuration debug
    print("\n🔧 Configuration Debug:")
    analyzer = debug_configuration()
    
    if not analyzer:
        print("❌ Configuration failed, stopping debug session")
        return
    
    # File debug
    print("\n📄 File Debug:")
    debug_file_parsing("session.har")
    
    # Analysis debug
    print("\n🔍 Analysis Debug:")
    try:
        result = await analyzer.analyze()
        print(f"✅ Analysis completed")
        print(f"   Issues: {len(result.issues)}")
        print(f"   Network traces: {len(result.network_traces)}")
        print(f"   Duration: {result.summary.analysis_duration_ms}ms")
        
    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n🐛 Debug session completed")

# Run comprehensive debug
asyncio.run(comprehensive_debug_session())
```

### Log Analysis

```python
def analyze_debug_logs(log_file="netstealth_debug.log"):
    """Analyze debug logs for common issues."""
    
    from pathlib import Path
    import re
    
    log_path = Path(log_file)
    
    if not log_path.exists():
        print(f"❌ Log file not found: {log_file}")
        return
    
    content = log_path.read_text()
    lines = content.split('\n')
    
    # Count log levels
    error_count = len([l for l in lines if 'ERROR' in l])
    warning_count = len([l for l in lines if 'WARNING' in l])
    debug_count = len([l for l in lines if 'DEBUG' in l])
    
    print(f"📊 Log Analysis:")
    print(f"   Errors: {error_count}")
    print(f"   Warnings: {warning_count}")
    print(f"   Debug messages: {debug_count}")
    
    # Find common error patterns
    common_errors = [
        r"FileNotFoundError",
        r"MemoryError",
        r"TimeoutError",
        r"JSONDecodeError",
        r"ConnectionError"
    ]
    
    for pattern in common_errors:
        matches = len(re.findall(pattern, content))
        if matches > 0:
            print(f"   {pattern}: {matches} occurrences")
    
    # Show recent errors
    error_lines = [l for l in lines if 'ERROR' in l]
    if error_lines:
        print(f"\n🚨 Recent Errors:")
        for error in error_lines[-5:]:  # Last 5 errors
            print(f"   {error}")

# Usage
analyze_debug_logs()
```

---

## 🆘 Getting Help

### Before Asking for Help

1. **Run System Diagnostics**:
```python
asyncio.run(system_diagnostics())
```

2. **Check Debug Logs**:
```python
analyze_debug_logs()
```

3. **Try Minimal Example**:
```python
async def minimal_test():
    analyzer = (NetStealthAnalyzer.create()
        .with_logs("small_test.har")
        .build())
    
    result = await analyzer.analyze()
    return result
```

### Reporting Issues

When reporting issues, include:

1. **System Information**:
   - Python version
   - Operating system
   - Available memory
   - NetStealth Analyzer version

2. **Configuration**:
   - Complete configuration code
   - Log file sizes and formats
   - Detector settings

3. **Error Details**:
   - Complete error message
   - Stack trace
   - Debug logs (if available)

4. **Reproduction Steps**:
   - Minimal code to reproduce
   - Sample data (if possible)
   - Expected vs actual behavior

### Community Resources

- **GitHub Issues**: [Report bugs](https://github.com/r4d4m4n71s/netstealth-analyzer/issues)
- **Discussions**: [Community help](https://github.com/r4d4m4n71s/netstealth-analyzer/discussions)
- **Documentation**: [Full documentation](https://github.com/r4d4m4n71s/netstealth-analyzer/wiki)

---

## 🔗 Related Documentation

- **[User Guide](USER_GUIDE.md)**: Complete usage guide
- **[Configuration Guide](CONFIGURATION.md)**: Configuration reference
- **[API Reference](API_REFERENCE.md)**: Complete API documentation
- **[Performance Guide](PERFORMANCE.md)**: Performance optimization

---

**NetStealth Analyzer v2.0 Troubleshooting Guide** - Last Updated: September 18, 2025
