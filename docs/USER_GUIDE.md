# 📖 NetStealth Analyzer v2.0 - User Guide

**Complete Guide to Network Stealth Analysis**

This comprehensive guide covers everything you need to know to effectively use NetStealth Analyzer for detecting proxy usage, browser automation, and network security issues.

---

## 📋 Table of Contents

1. [Getting Started](#getting-started)
2. [Basic Usage](#basic-usage)
3. [Advanced Features](#advanced-features)
4. [Log File Formats](#log-file-formats)
5. [Detection Capabilities](#detection-capabilities)
6. [Report Generation](#report-generation)
7. [Event Handling](#event-handling)
8. [Performance Optimization](#performance-optimization)
9. [Common Use Cases](#common-use-cases)
10. [Troubleshooting](#troubleshooting)

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.13+** (recommended) or Python 3.11+
- **Poetry** (recommended) or pip for package management
- **Git** for cloning the repository

### Installation

#### Option 1: Using Poetry (Recommended)
```bash
# Clone the repository
git clone https://github.com/r4d4m4n71s/netstealth-analyzer.git
cd netstealth-analyzer

# Install dependencies
poetry install

# Activate virtual environment
poetry shell
```

#### Option 2: Using pip
```bash
# Clone and install
git clone https://github.com/r4d4m4n71s/netstealth-analyzer.git
cd netstealth-analyzer
pip install -e .
```

### Verify Installation

```python
import asyncio
from netstealth_analyzer import NetStealthAnalyzer

async def test_installation():
    print("NetStealth Analyzer installed successfully!")
    analyzer = NetStealthAnalyzer.create()
    print(f"Version: 2.0.0")

asyncio.run(test_installation())
```

---

## 🎯 Basic Usage

### Your First Analysis

Let's start with a simple analysis of a HAR file:

```python
import asyncio
from netstealth_analyzer import NetStealthAnalyzer

async def basic_analysis():
    # Create analyzer with fluent API
    analyzer = (NetStealthAnalyzer.create()
                .with_logs("session.har")
                .for_service("example.com")
                .build())
    
    # Run analysis
    result = await analyzer.analyze()
    
    # Print summary
    print(f"Analysis completed!")
    print(f"Overall Score: {result.summary.overall_score}/100")
    print(f"Issues Found: {len(result.issues)}")
    
    # Show high-severity issues
    for issue in result.issues:
        if issue.severity.value in ['high', 'critical']:
            print(f"🚨 {issue.title} ({issue.severity.value})")

# Run the analysis
asyncio.run(basic_analysis())
```

### Understanding the Results

The analysis returns an `AnalysisResult` object with:

- **Overall Score**: 0-100 security score
- **Issues**: List of detected security problems
- **Network Traces**: Network routing information
- **Performance Metrics**: Analysis performance data

### Basic Configuration Options

```python
analyzer = (NetStealthAnalyzer.create()
    .with_logs("session.har")                    # Input log file
    .for_service("example.com")                  # Target service domain
    .with_detectors(["proxy", "browser"])        # Specific detectors
    .track_progress(progress_callback)           # Progress tracking
    .build())
```

---

## 🔧 Advanced Features

### Multiple Log Files

Analyze multiple log files from different sources:

```python
async def multi_file_analysis():
    analyzer = (NetStealthAnalyzer.create()
        .with_logs([
            "session.har",           # Browser session
            "mitmproxy.log",         # Proxy logs
            "automation.log"         # Browser automation logs
        ])
        .for_service(["example.com", "api.service.com"])
        .build())
    
    result = await analyzer.analyze()
    return result
```

### Streaming Analysis

For large files or real-time processing:

```python
async def streaming_analysis():
    analyzer = (NetStealthAnalyzer.create()
        .with_logs("large_session.har")
        .for_service("example.com")
        .build())
    
    # Process results as they come
    async for update in analyzer.stream_analysis():
        if update['type'] == 'issue_found':
            print(f"Issue: {update['title']}")
        elif update['type'] == 'progress':
            print(f"Progress: {update['percentage']:.1f}%")
```

### Custom Event Handling

Monitor analysis progress with detailed events:

```python
from netstealth_analyzer.core.events import AnalysisEvent

async def event_driven_analysis():
    analyzer = NetStealthAnalyzer.create()
    
    # Configure event handlers
    async def on_issue_found(event, data):
        severity_icons = {
            'critical': '💥', 'high': '🚨', 
            'medium': '⚠️', 'low': 'ℹ️'
        }
        icon = severity_icons.get(data.severity, '❓')
        print(f"{icon} {data.title}")
    
    async def on_progress(event, data):
        print(f"Progress: {data.percentage:.1f}% - {data.message}")
    
    # Register handlers
    analyzer.on_event(AnalysisEvent.ISSUE_FOUND, on_issue_found)
    analyzer.on_event(AnalysisEvent.PROGRESS_UPDATE, on_progress)
    
    # Configure and run
    analyzer.with_logs("session.har").for_service("example.com")
    built_analyzer = analyzer.build()
    
    result = await built_analyzer.analyze()
    return result
```

### Geographic Analysis

Analyze traffic for geographic inconsistencies:

```python
async def geographic_analysis():
    analyzer = (NetStealthAnalyzer.create()
        .with_logs("session.har")
        .for_service("example.com")
        .in_geography("US")  # Expected country
        .build())
    
    result = await analyzer.analyze()
    
    # Check for geographic issues
    geo_issues = [issue for issue in result.issues 
                  if 'geographic' in issue.category.value.lower()]
    
    for issue in geo_issues:
        print(f"Geographic Issue: {issue.title}")
        print(f"Description: {issue.description}")
```

---

## 📁 Log File Formats

NetStealth Analyzer supports multiple log formats:

### HAR Files (.har)

**Best for**: Browser-based analysis, complete HTTP data

```python
# HAR files contain complete request/response data
analyzer.with_logs("browser_session.har")
```

**What's Analyzed**:
- HTTP requests and responses
- Timing information
- Headers and cookies
- TLS handshake data
- WebSocket connections

### Mitmproxy Logs (.log)

**Best for**: Proxy analysis, traffic interception

```python
# Mitmproxy debug logs
analyzer.with_logs("mitmproxy_session.log")
```

**What's Analyzed**:
- Proxy flow information
- Request/response correlation
- Connection details
- Error handling

### Browser Automation Logs

**Best for**: Detecting automation tools

```python
# Browser automation detection
analyzer.with_logs("selenium_session.log")
```

**What's Analyzed**:
- WebDriver signatures
- Automation tool patterns
- JavaScript execution traces
- Browser fingerprinting

### Multiple Format Analysis

```python
# Analyze different formats together
analyzer.with_logs([
    ("session.har", LogFormat.HAR),
    ("proxy.log", LogFormat.MITMPROXY),
    ("automation.log", LogFormat.BROWSER_CONSOLE)
])
```

---

## 🔍 Detection Capabilities

### Proxy Detection

Identifies various proxy usage indicators:

```python
# Focus on proxy detection
analyzer.with_detectors(["proxy"])

# What gets detected:
# - HTTP proxy headers (X-Forwarded-For, Via)
# - IP geolocation inconsistencies
# - WebRTC IP leaks
# - Datacenter IP usage
# - VPN service detection
# - DNS leak analysis
```

**Example Issues Detected**:
- "Proxy Headers Detected" - X-Forwarded-For header found
- "IP Geolocation Mismatch" - IP location doesn't match expected
- "WebRTC IP Leak" - Real IP exposed via WebRTC
- "Datacenter IP Usage" - Traffic from hosting provider

### Browser Automation Detection

Identifies automated browser usage:

```python
# Focus on browser automation
analyzer.with_detectors(["browser"])

# What gets detected:
# - Selenium WebDriver signatures
# - Headless browser indicators
# - Automation framework patterns
# - JavaScript fingerprinting
# - User agent analysis
# - Behavioral patterns
```

**Example Issues Detected**:
- "Selenium WebDriver Detected" - WebDriver automation signatures
- "Headless Browser Usage" - Headless Chrome/Firefox detected
- "Automation Framework Pattern" - Puppeteer/Playwright signatures
- "JavaScript Fingerprinting" - Canvas/WebGL fingerprinting detected

### Network Analysis

Analyzes network routing and anomalies:

```python
# Focus on network analysis
analyzer.with_detectors(["network"])

# What gets detected:
# - Unusual routing patterns
# - Geographic inconsistencies
# - Latency analysis
# - Proxy chain detection
# - Tor exit node identification
# - Security service detection
```

**Example Issues Detected**:
- "Unusual Routing Pattern" - Unexpected network hops
- "Geographic Inconsistency" - Location mismatch
- "Tor Exit Node Detected" - Traffic via Tor network
- "Security Service Intervention" - Cloudflare/Akamai detected

### TLS Analysis

Examines TLS connections and certificates:

```python
# Focus on TLS analysis
analyzer.with_detectors(["tls"])

# What gets detected:
# - Certificate validation issues
# - TLS version problems
# - Cipher suite analysis
# - Handshake patterns
# - Certificate chain validation
```

**Example Issues Detected**:
- "Weak TLS Version" - TLS 1.0/1.1 usage
- "Certificate Validation Error" - Invalid certificate
- "Suspicious TLS Handshake" - Automation-like handshake

---

## 📊 Report Generation

### Multiple Report Formats

Generate reports in various formats:

```python
async def generate_reports():
    analyzer = (NetStealthAnalyzer.create()
        .with_logs("session.har")
        .for_service("example.com")
        .build())
    
    result = await analyzer.analyze()
    
    # Generate multiple report formats
    await analyzer.report(result, format="html", output="report.html")
    await analyzer.report(result, format="json", output="results.json")
    await analyzer.report(result, format="markdown", output="summary.md")
    await analyzer.report(result, format="yaml", output="data.yaml")
```

### HTML Reports

Rich, interactive HTML reports with:
- Executive summary
- Issue details with evidence
- Network trace visualization
- Performance metrics
- Remediation suggestions

### JSON Reports

Machine-readable format for:
- API integration
- Automated processing
- Data analysis
- CI/CD pipelines

### Custom Report Processing

```python
async def custom_report_processing():
    result = await analyzer.analyze()
    
    # Process results programmatically
    critical_issues = result.get_issues_by_severity("critical")
    
    # Create custom summary
    summary = {
        'total_issues': len(result.issues),
        'critical_count': len(critical_issues),
        'overall_score': result.summary.overall_score,
        'analysis_time': result.summary.analysis_duration_ms,
        'recommendations': []
    }
    
    # Add recommendations based on issues
    for issue in critical_issues:
        for remediation in issue.remediation_suggestions:
            summary['recommendations'].append({
                'issue': issue.title,
                'action': remediation.description,
                'priority': 'high'
            })
    
    return summary
```

---

## 🎛️ Event Handling

### Available Events

Monitor analysis progress with these events:

```python
from netstealth_analyzer.core.events import AnalysisEvent

# Analysis lifecycle events
AnalysisEvent.ANALYSIS_STARTED
AnalysisEvent.ANALYSIS_COMPLETED
AnalysisEvent.ANALYSIS_FAILED

# Progress events
AnalysisEvent.PROGRESS_UPDATE
AnalysisEvent.STAGE_STARTED
AnalysisEvent.STAGE_COMPLETED

# Detection events
AnalysisEvent.ISSUE_FOUND
AnalysisEvent.DETECTOR_STARTED
AnalysisEvent.DETECTOR_COMPLETED

# Parsing events
AnalysisEvent.PARSER_STARTED
AnalysisEvent.LOG_ENTRY_PARSED
```

### Event Handler Examples

```python
async def comprehensive_event_handling():
    analyzer = NetStealthAnalyzer.create()
    
    # Track analysis progress
    async def on_progress(event, data):
        print(f"Progress: {data.percentage:.1f}% - {data.message}")
    
    # Handle found issues
    async def on_issue_found(event, data):
        print(f"🔍 Found: {data.title}")
        print(f"   Severity: {data.severity}")
        print(f"   Confidence: {data.confidence:.1%}")
    
    # Track stage completion
    async def on_stage_completed(event, data):
        print(f"✅ Completed: {data.stage_name} ({data.duration_ms}ms)")
    
    # Handle errors
    async def on_analysis_failed(event, data):
        print(f"❌ Analysis failed: {data.error_message}")
    
    # Register all handlers
    analyzer.on_event(AnalysisEvent.PROGRESS_UPDATE, on_progress)
    analyzer.on_event(AnalysisEvent.ISSUE_FOUND, on_issue_found)
    analyzer.on_event(AnalysisEvent.STAGE_COMPLETED, on_stage_completed)
    analyzer.on_event(AnalysisEvent.ANALYSIS_FAILED, on_analysis_failed)
    
    # Configure and run
    analyzer.with_logs("session.har").for_service("example.com")
    result = await analyzer.build().analyze()
    
    return result
```

---

## ⚡ Performance Optimization

### Large File Handling

For large log files (>100MB):

```python
async def large_file_analysis():
    analyzer = (NetStealthAnalyzer.create()
        .with_logs("large_session.har")
        .for_service("example.com")
        .max_concurrent_parsers(4)      # Parallel processing
        .memory_limit(512)              # 512MB memory limit
        .timeout(600)                   # 10 minute timeout
        .build())
    
    # Use streaming for memory efficiency
    async for update in analyzer.stream_analysis():
        if update['type'] == 'issue_found':
            # Process issues immediately
            process_issue(update)
```

### Concurrent Analysis

Process multiple files concurrently:

```python
async def concurrent_analysis():
    files = ["session1.har", "session2.har", "session3.har"]
    
    # Create tasks for concurrent processing
    tasks = []
    for file in files:
        analyzer = (NetStealthAnalyzer.create()
            .with_logs(file)
            .for_service("example.com")
            .build())
        
        task = asyncio.create_task(analyzer.analyze())
        tasks.append(task)
    
    # Wait for all analyses to complete
    results = await asyncio.gather(*tasks)
    
    # Combine results
    combined_issues = []
    for result in results:
        combined_issues.extend(result.issues)
    
    return combined_issues
```

### Memory Management

```python
async def memory_efficient_analysis():
    # Use context manager for automatic cleanup
    async with NetStealthAnalyzer.create().with_logs("session.har").build() as analyzer:
        result = await analyzer.analyze()
        
        # Process results immediately
        process_results(result)
        
        # Analyzer automatically cleaned up on exit
```

---

## 🎯 Common Use Cases

### Use Case 1: Proxy Detection Audit

**Scenario**: Verify that proxy usage is properly configured and not leaking real IP

```python
async def proxy_audit():
    analyzer = (NetStealthAnalyzer.create()
        .with_logs("proxy_session.har")
        .for_service("target-service.com")
        .with_detectors(["proxy", "network"])
        .build())
    
    result = await analyzer.analyze()
    
    # Check for proxy-related issues
    proxy_issues = [issue for issue in result.issues 
                   if 'proxy' in issue.category.value.lower()]
    
    if not proxy_issues:
        print("✅ Proxy configuration appears secure")
    else:
        print("🚨 Proxy issues detected:")
        for issue in proxy_issues:
            print(f"  - {issue.title}")
            for suggestion in issue.remediation_suggestions:
                print(f"    💡 {suggestion.description}")
```

### Use Case 2: Browser Automation Detection

**Scenario**: Detect if browser automation is being detected by target service

```python
async def automation_detection_check():
    analyzer = (NetStealthAnalyzer.create()
        .with_logs("automation_session.har")
        .for_service("target-service.com")
        .with_detectors(["browser"])
        .build())
    
    result = await analyzer.analyze()
    
    # Analyze automation detection
    automation_issues = [issue for issue in result.issues 
                        if 'automation' in issue.title.lower() or 
                           'webdriver' in issue.title.lower()]
    
    if automation_issues:
        print("🤖 Automation detected by service:")
        for issue in automation_issues:
            print(f"  Method: {issue.title}")
            print(f"  Confidence: {issue.confidence:.1%}")
            
            # Show evidence
            for evidence in issue.evidence:
                print(f"  Evidence: {evidence.description}")
```

### Use Case 3: Geographic Consistency Check

**Scenario**: Ensure all traffic appears to originate from expected location

```python
async def geographic_consistency_check():
    analyzer = (NetStealthAnalyzer.create()
        .with_logs("session.har")
        .for_service("geo-restricted-service.com")
        .in_geography("US")  # Expected location
        .with_detectors(["network", "proxy"])
        .build())
    
    result = await analyzer.analyze()
    
    # Check geographic consistency
    geo_issues = [issue for issue in result.issues 
                 if 'geographic' in issue.category.value.lower()]
    
    if not geo_issues:
        print("🌍 Geographic consistency maintained")
    else:
        print("🗺️ Geographic inconsistencies detected:")
        for issue in geo_issues:
            print(f"  Issue: {issue.title}")
            print(f"  Impact: {issue.description}")
```

### Use Case 4: Comprehensive Security Audit

**Scenario**: Complete security analysis of web scraping setup

```python
async def comprehensive_security_audit():
    analyzer = (NetStealthAnalyzer.create()
        .with_logs([
            "browser_session.har",
            "proxy_logs.log",
            "automation_debug.log"
        ])
        .for_service(["target1.com", "target2.com"])
        .with_detectors("all")  # Use all detectors
        .build())
    
    result = await analyzer.analyze()
    
    # Generate comprehensive report
    audit_report = {
        'overall_score': result.summary.overall_score,
        'risk_level': 'HIGH' if result.summary.overall_score < 70 else 'MEDIUM' if result.summary.overall_score < 85 else 'LOW',
        'issues_by_severity': {},
        'recommendations': [],
        'network_analysis': {
            'total_traces': len(result.network_traces),
            'unique_ips': len(set(trace.client_ip for trace in result.network_traces if hasattr(trace, 'client_ip')))
        }
    }
    
    # Categorize issues by severity
    for severity in ['critical', 'high', 'medium', 'low']:
        issues = result.get_issues_by_severity(severity)
        audit_report['issues_by_severity'][severity] = len(issues)
        
        # Add top recommendations for high-severity issues
        if severity in ['critical', 'high']:
            for issue in issues[:3]:  # Top 3 issues
                for suggestion in issue.remediation_suggestions:
                    audit_report['recommendations'].append({
                        'issue': issue.title,
                        'action': suggestion.description,
                        'priority': severity
                    })
    
    return audit_report
```

---

## 🔧 Troubleshooting

### Common Issues and Solutions

#### Issue: "No log files configured for analysis"

**Solution**: Ensure you've added log files before building the analyzer

```python
# ❌ Wrong
analyzer = NetStealthAnalyzer.create().build()

# ✅ Correct
analyzer = NetStealthAnalyzer.create().with_logs("session.har").build()
```

#### Issue: "Failed to parse log file"

**Solution**: Verify file format and specify format explicitly

```python
# Auto-detect format (may fail)
analyzer.with_logs("session.log")

# Specify format explicitly
from netstealth_analyzer.models.enums import LogFormat
analyzer.with_logs([("session.log", LogFormat.MITMPROXY)])
```

#### Issue: Analysis timeout

**Solution**: Increase timeout for large files

```python
analyzer = (NetStealthAnalyzer.create()
    .with_logs("large_file.har")
    .timeout(600)  # 10 minutes
    .build())
```

#### Issue: Memory errors with large files

**Solution**: Use streaming analysis or set memory limits

```python
# Option 1: Streaming analysis
async for update in analyzer.stream_analysis():
    process_update(update)

# Option 2: Memory limit
analyzer.memory_limit(256)  # 256MB limit
```

#### Issue: No issues detected when expected

**Solution**: Check detector configuration and confidence threshold

```python
# Lower confidence threshold
analyzer = (NetStealthAnalyzer.create()
    .with_logs("session.har")
    .for_service("example.com")
    .build())

# Check if specific detectors are enabled
analyzer.with_detectors(["proxy", "browser", "network", "tls"])
```

### Debug Mode

Enable detailed logging for troubleshooting:

```python
import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('netstealth_analyzer')
logger.setLevel(logging.DEBUG)

# Run analysis with debug output
result = await analyzer.analyze()
```

### Validation

Validate your configuration before running analysis:

```python
async def validate_setup():
    analyzer = NetStealthAnalyzer.create()
    
    # Configure analyzer
    analyzer.with_logs("session.har").for_service("example.com")
    
    # Validate configuration
    try:
        validated_analyzer = analyzer.validate().build()
        print("✅ Configuration valid")
        return validated_analyzer
    except Exception as e:
        print(f"❌ Configuration error: {e}")
        return None
```

---

## 📚 Next Steps

### Advanced Topics

- **[Configuration Guide](CONFIGURATION.md)**: Detailed configuration options
- **[Plugin Development](PLUGIN_DEVELOPMENT.md)**: Create custom detectors
- **[Performance Guide](PERFORMANCE.md)**: Optimization techniques
- **[Best Practices](BEST_PRACTICES.md)**: Security analysis best practices

### Examples

- **[Basic Examples](../examples/basic_usage/)**: Simple use cases
- **[Advanced Workflows](../examples/advanced_workflows/)**: Complex scenarios
- **[Integration Examples](../examples/integrations/)**: CI/CD and monitoring

### Support

- **[Troubleshooting Guide](TROUBLESHOOTING.md)**: Common issues and solutions
- **[GitHub Issues](https://github.com/r4d4m4n71s/netstealth-analyzer/issues)**: Report bugs
- **[Discussions](https://github.com/r4d4m4n71s/netstealth-analyzer/discussions)**: Community support

---

**NetStealth Analyzer v2.0 User Guide** - Last Updated: September 18, 2025
