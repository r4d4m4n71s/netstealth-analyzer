# ⚙️ NetStealth Analyzer v2.0 - Configuration Guide

**Complete Configuration Reference**

This guide covers all configuration options available in NetStealth Analyzer, from basic settings to advanced customization.

---

## 📋 Table of Contents

1. [Configuration Overview](#configuration-overview)
2. [Basic Configuration](#basic-configuration)
3. [Advanced Configuration](#advanced-configuration)
4. [Detector Configuration](#detector-configuration)
5. [Performance Configuration](#performance-configuration)
6. [Event Configuration](#event-configuration)
7. [Output Configuration](#output-configuration)
8. [Configuration Files](#configuration-files)
9. [Environment Variables](#environment-variables)
10. [Validation and Testing](#validation-and-testing)

---

## 🎯 Configuration Overview

NetStealth Analyzer offers multiple ways to configure analysis behavior:

### Configuration Methods

1. **Fluent API** - Method chaining (recommended for code)
2. **Configuration Objects** - Structured configuration
3. **Configuration Files** - JSON/YAML files
4. **Environment Variables** - Runtime configuration

### Configuration Hierarchy

```
Environment Variables (highest priority)
    ↓
Configuration Files
    ↓
Fluent API Configuration
    ↓
Default Values (lowest priority)
```

---

## 🔧 Basic Configuration

### Input Configuration

#### Single Log File

```python
from netstealth_analyzer import NetStealthAnalyzer

# Basic single file
analyzer = (NetStealthAnalyzer.create()
    .with_logs("session.har")
    .build())

# With explicit format
from netstealth_analyzer.models.enums import LogFormat
analyzer = (NetStealthAnalyzer.create()
    .with_logs([("session.har", LogFormat.HAR)])
    .build())
```

#### Multiple Log Files

```python
# Multiple files (auto-detect format)
analyzer = (NetStealthAnalyzer.create()
    .with_logs([
        "session.har",
        "proxy.log",
        "automation.log"
    ])
    .build())

# Multiple files with explicit formats
analyzer = (NetStealthAnalyzer.create()
    .with_logs([
        ("session.har", LogFormat.HAR),
        ("proxy.log", LogFormat.MITMPROXY),
        ("automation.log", LogFormat.BROWSER_CONSOLE)
    ])
    .build())
```

#### Directory-based Input

```python
# All files in directory
analyzer = (NetStealthAnalyzer.create()
    .with_log_directory("./logs")
    .build())

# With pattern matching
analyzer = (NetStealthAnalyzer.create()
    .with_log_directory("./logs", pattern="*.har")
    .build())

# Recursive directory scan
analyzer = (NetStealthAnalyzer.create()
    .with_log_directory("./logs", pattern="*.har", recursive=True)
    .build())
```

### Target Configuration

#### Service Domains

```python
# Single service
analyzer = (NetStealthAnalyzer.create()
    .for_service("example.com")
    .build())

# Multiple services
analyzer = (NetStealthAnalyzer.create()
    .for_service(["example.com", "api.service.com", "cdn.service.com"])
    .build())
```

#### Geographic Configuration

```python
# Expected country
analyzer = (NetStealthAnalyzer.create()
    .in_geography("US")
    .build())

# Multiple acceptable countries
analyzer = (NetStealthAnalyzer.create()
    .in_geography(["US", "CA", "GB"])
    .build())
```

---

## 🚀 Advanced Configuration

### Detector Selection

#### Specific Detectors

```python
# Individual detectors
analyzer = (NetStealthAnalyzer.create()
    .with_detectors(["proxy", "browser"])
    .build())

# All detectors
analyzer = (NetStealthAnalyzer.create()
    .with_detectors("all")
    .build())

# Exclude specific detectors
analyzer = (NetStealthAnalyzer.create()
    .with_detectors("all")
    .exclude_detectors(["tls"])  # All except TLS
    .build())
```

#### Custom Detector Configuration

```python
from netstealth_analyzer.detectors.proxy import ProxyDetector
from netstealth_analyzer.detectors.browser import BrowserDetector

# Custom detector instances
custom_proxy = ProxyDetector(confidence_threshold=0.8)
custom_browser = BrowserDetector(strict_mode=True)

analyzer = (NetStealthAnalyzer.create()
    .with_detector(custom_proxy)
    .with_detector(custom_browser)
    .build())
```

### Analysis Features

#### Feature Flags

```python
analyzer = (NetStealthAnalyzer.create()
    .enable_streaming()              # Enable streaming analysis
    .enable_fingerprint_analysis()   # Detailed fingerprinting
    .enable_session_timeline()       # Session timeline generation
    .enable_diff_analysis()          # Differential analysis
    .build())
```

#### Analysis Modes

```python
# Quick analysis (basic detectors only)
analyzer = (NetStealthAnalyzer.create()
    .quick_mode()
    .build())

# Comprehensive analysis (all detectors, detailed analysis)
analyzer = (NetStealthAnalyzer.create()
    .comprehensive_mode()
    .build())

# Custom analysis mode
analyzer = (NetStealthAnalyzer.create()
    .analysis_mode("custom")
    .with_detectors(["proxy", "network"])
    .build())
```

---

## 🔍 Detector Configuration

### Proxy Detector Configuration

```python
from netstealth_analyzer.detectors.proxy import ProxyDetector

# Basic configuration
proxy_detector = ProxyDetector(
    confidence_threshold=0.7,
    strict_mode=False
)

# Advanced configuration
proxy_detector = ProxyDetector(
    confidence_threshold=0.8,
    strict_mode=True,
    check_webrtc_leaks=True,
    check_dns_leaks=True,
    datacenter_ip_detection=True,
    vpn_service_detection=True
)

analyzer = (NetStealthAnalyzer.create()
    .with_detector(proxy_detector)
    .build())
```

### Browser Detector Configuration

```python
from netstealth_analyzer.detectors.browser import BrowserDetector

# Basic configuration
browser_detector = BrowserDetector(
    confidence_threshold=0.7,
    check_automation_signatures=True
)

# Advanced configuration
browser_detector = BrowserDetector(
    confidence_threshold=0.8,
    check_automation_signatures=True,
    check_headless_indicators=True,
    check_webdriver_properties=True,
    check_javascript_fingerprinting=True,
    user_agent_analysis=True,
    behavioral_analysis=True
)

analyzer = (NetStealthAnalyzer.create()
    .with_detector(browser_detector)
    .build())
```

### Network Detector Configuration

```python
from netstealth_analyzer.detectors.network import NetworkDetector

# Advanced network analysis
network_detector = NetworkDetector(
    confidence_threshold=0.7,
    check_routing_anomalies=True,
    check_geographic_consistency=True,
    check_latency_patterns=True,
    check_tor_usage=True,
    check_security_services=True
)

analyzer = (NetStealthAnalyzer.create()
    .with_detector(network_detector)
    .build())
```

### TLS Detector Configuration

```python
from netstealth_analyzer.detectors.tls import TLSDetector

# TLS security analysis
tls_detector = TLSDetector(
    confidence_threshold=0.7,
    check_certificate_validation=True,
    check_tls_versions=True,
    check_cipher_suites=True,
    check_handshake_patterns=True,
    ja3_fingerprinting=True
)

analyzer = (NetStealthAnalyzer.create()
    .with_detector(tls_detector)
    .build())
```

---

## ⚡ Performance Configuration

### Concurrency Settings

```python
analyzer = (NetStealthAnalyzer.create()
    .max_concurrent_parsers(4)       # Parallel parsing
    .max_concurrent_detectors(2)     # Parallel detection
    .max_concurrent_stages(8)        # Pipeline parallelism
    .build())
```

### Memory Management

```python
analyzer = (NetStealthAnalyzer.create()
    .memory_limit(512)               # 512MB limit
    .streaming_threshold(100)        # Stream files >100MB
    .chunk_size(1024)               # 1KB chunks for streaming
    .build())
```

### Timeout Configuration

```python
analyzer = (NetStealthAnalyzer.create()
    .timeout(300)                    # Overall timeout (5 minutes)
    .parser_timeout(60)              # Parser timeout (1 minute)
    .detector_timeout(120)           # Detector timeout (2 minutes)
    .build())
```

### Caching Configuration

```python
analyzer = (NetStealthAnalyzer.create()
    .enable_caching()                # Enable result caching
    .cache_size(100)                 # Cache 100 results
    .cache_ttl(3600)                 # 1 hour TTL
    .build())
```

---

## 📡 Event Configuration

### Progress Tracking

```python
def progress_callback(current, total, message):
    percentage = (current / total) * 100 if total > 0 else 0
    print(f"Progress: {percentage:.1f}% - {message}")

analyzer = (NetStealthAnalyzer.create()
    .track_progress(progress_callback)
    .build())
```

### Event Handlers

```python
from netstealth_analyzer.core.events import AnalysisEvent

async def issue_handler(event, data):
    print(f"Issue found: {data.title}")

async def error_handler(event, data):
    print(f"Error: {data.error_message}")

analyzer = (NetStealthAnalyzer.create()
    .on_event(AnalysisEvent.ISSUE_FOUND, issue_handler)
    .on_event(AnalysisEvent.ANALYSIS_FAILED, error_handler)
    .build())
```

### Event Filtering

```python
# Only high-severity issues
async def high_severity_filter(event, data):
    if data.severity in ['high', 'critical']:
        print(f"High severity issue: {data.title}")

analyzer = (NetStealthAnalyzer.create()
    .on_event(AnalysisEvent.ISSUE_FOUND, high_severity_filter)
    .build())
```

---

## 📄 Output Configuration

### Report Formats

```python
analyzer = (NetStealthAnalyzer.create()
    .output_formats("html", "json", "markdown")
    .output_to("./reports")
    .build())

# After analysis
result = await analyzer.analyze()
await analyzer.generate_reports(result)  # Generates all configured formats
```

### Custom Output Configuration

```python
analyzer = (NetStealthAnalyzer.create()
    .output_to("./reports")
    .include_raw_data(True)          # Include raw log data
    .include_network_traces(True)    # Include network traces
    .include_performance_metrics(True) # Include performance data
    .compress_output(True)           # Compress large reports
    .build())
```

### Report Customization

```python
from netstealth_analyzer.reporting.formats import ReportConfig

# Custom HTML report
html_config = ReportConfig(
    format="html",
    template="custom_template.html",
    include_charts=True,
    include_timeline=True,
    theme="dark"
)

# Custom JSON report
json_config = ReportConfig(
    format="json",
    pretty_print=True,
    include_metadata=True,
    exclude_raw_data=False
)

analyzer = (NetStealthAnalyzer.create()
    .with_report_config(html_config)
    .with_report_config(json_config)
    .build())
```

---

## 📁 Configuration Files

### JSON Configuration

Create `netstealth_config.json`:

```json
{
  "input": {
    "log_files": [
      {
        "path": "session.har",
        "format": "har"
      },
      {
        "path": "proxy.log",
        "format": "mitmproxy"
      }
    ],
    "log_directories": [
      {
        "path": "./logs",
        "pattern": "*.har",
        "recursive": true
      }
    ]
  },
  "target": {
    "service_domains": ["example.com", "api.service.com"],
    "geography": "US"
  },
  "detectors": {
    "enabled": ["proxy", "browser", "network"],
    "proxy": {
      "confidence_threshold": 0.8,
      "strict_mode": true,
      "check_webrtc_leaks": true,
      "check_dns_leaks": true
    },
    "browser": {
      "confidence_threshold": 0.7,
      "check_automation_signatures": true,
      "check_headless_indicators": true
    },
    "network": {
      "confidence_threshold": 0.7,
      "check_routing_anomalies": true,
      "check_geographic_consistency": true
    }
  },
  "performance": {
    "max_concurrent_parsers": 4,
    "max_concurrent_detectors": 2,
    "memory_limit_mb": 512,
    "timeout_seconds": 300
  },
  "output": {
    "directory": "./reports",
    "formats": ["html", "json"],
    "include_raw_data": false,
    "compress_output": true
  },
  "features": {
    "streaming_analysis": true,
    "fingerprint_analysis": true,
    "session_timeline": false,
    "diff_analysis": false
  }
}
```

### YAML Configuration

Create `netstealth_config.yaml`:

```yaml
input:
  log_files:
    - path: "session.har"
      format: "har"
    - path: "proxy.log"
      format: "mitmproxy"
  
  log_directories:
    - path: "./logs"
      pattern: "*.har"
      recursive: true

target:
  service_domains:
    - "example.com"
    - "api.service.com"
  geography: "US"

detectors:
  enabled:
    - "proxy"
    - "browser"
    - "network"
  
  proxy:
    confidence_threshold: 0.8
    strict_mode: true
    check_webrtc_leaks: true
    check_dns_leaks: true
  
  browser:
    confidence_threshold: 0.7
    check_automation_signatures: true
    check_headless_indicators: true
  
  network:
    confidence_threshold: 0.7
    check_routing_anomalies: true
    check_geographic_consistency: true

performance:
  max_concurrent_parsers: 4
  max_concurrent_detectors: 2
  memory_limit_mb: 512
  timeout_seconds: 300

output:
  directory: "./reports"
  formats:
    - "html"
    - "json"
  include_raw_data: false
  compress_output: true

features:
  streaming_analysis: true
  fingerprint_analysis: true
  session_timeline: false
  diff_analysis: false
```

### Loading Configuration Files

```python
# Load JSON configuration
analyzer = (NetStealthAnalyzer.create()
    .with_config_file("netstealth_config.json")
    .build())

# Load YAML configuration
analyzer = (NetStealthAnalyzer.create()
    .with_config_file("netstealth_config.yaml")
    .build())

# Load and override specific settings
analyzer = (NetStealthAnalyzer.create()
    .with_config_file("netstealth_config.json")
    .timeout(600)  # Override timeout from config
    .build())
```

---

## 🌍 Environment Variables

### Basic Environment Variables

```bash
# Input configuration
export NETSTEALTH_LOG_FILES="session.har,proxy.log"
export NETSTEALTH_LOG_DIRECTORY="./logs"

# Target configuration
export NETSTEALTH_SERVICE_DOMAINS="example.com,api.service.com"
export NETSTEALTH_GEOGRAPHY="US"

# Detector configuration
export NETSTEALTH_DETECTORS="proxy,browser,network"
export NETSTEALTH_CONFIDENCE_THRESHOLD="0.8"

# Performance configuration
export NETSTEALTH_MAX_CONCURRENT_PARSERS="4"
export NETSTEALTH_MEMORY_LIMIT_MB="512"
export NETSTEALTH_TIMEOUT_SECONDS="300"

# Output configuration
export NETSTEALTH_OUTPUT_DIRECTORY="./reports"
export NETSTEALTH_OUTPUT_FORMATS="html,json"
```

### Advanced Environment Variables

```bash
# Feature flags
export NETSTEALTH_ENABLE_STREAMING="true"
export NETSTEALTH_ENABLE_FINGERPRINT_ANALYSIS="true"
export NETSTEALTH_ENABLE_SESSION_TIMELINE="false"

# Detector-specific settings
export NETSTEALTH_PROXY_STRICT_MODE="true"
export NETSTEALTH_PROXY_CHECK_WEBRTC="true"
export NETSTEALTH_BROWSER_CHECK_AUTOMATION="true"
export NETSTEALTH_NETWORK_CHECK_ROUTING="true"

# Debug settings
export NETSTEALTH_DEBUG="true"
export NETSTEALTH_LOG_LEVEL="DEBUG"
export NETSTEALTH_VERBOSE="true"
```

### Using Environment Variables

```python
import os
from netstealth_analyzer import NetStealthAnalyzer

# Environment variables are automatically loaded
analyzer = NetStealthAnalyzer.create()

# Check if environment variable is set
if os.getenv('NETSTEALTH_LOG_FILES'):
    # Will use environment variable
    analyzer = analyzer.build()
else:
    # Fallback to manual configuration
    analyzer = analyzer.with_logs("session.har").build()
```

---

## ✅ Validation and Testing

### Configuration Validation

```python
async def validate_configuration():
    try:
        analyzer = (NetStealthAnalyzer.create()
            .with_logs("session.har")
            .for_service("example.com")
            .validate()  # Validate configuration
            .build())
        
        print("✅ Configuration is valid")
        return analyzer
        
    except ValueError as e:
        print(f"❌ Configuration error: {e}")
        return None
    except FileNotFoundError as e:
        print(f"❌ File not found: {e}")
        return None
```

### Configuration Testing

```python
async def test_configuration():
    """Test configuration with a small sample."""
    
    # Create test configuration
    analyzer = (NetStealthAnalyzer.create()
        .with_logs("test_session.har")
        .for_service("example.com")
        .with_detectors(["proxy"])
        .timeout(60)  # Short timeout for testing
        .build())
    
    try:
        # Run quick test
        result = await analyzer.analyze()
        
        print(f"✅ Configuration test passed")
        print(f"   Issues found: {len(result.issues)}")
        print(f"   Analysis time: {result.summary.analysis_duration_ms}ms")
        
        return True
        
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False
```

### Configuration Debugging

```python
def debug_configuration():
    """Debug current configuration."""
    
    analyzer = NetStealthAnalyzer.create()
    
    # Add configuration step by step
    print("🔧 Building configuration...")
    
    analyzer = analyzer.with_logs("session.har")
    print("   ✅ Added log file")
    
    analyzer = analyzer.for_service("example.com")
    print("   ✅ Set service domain")
    
    analyzer = analyzer.with_detectors(["proxy", "browser"])
    print("   ✅ Configured detectors")
    
    try:
        built_analyzer = analyzer.validate().build()
        print("   ✅ Configuration validated")
        
        # Print configuration summary
        config = built_analyzer.config
        print(f"\n📋 Configuration Summary:")
        print(f"   Log files: {len(config.input_files)}")
        print(f"   Service domains: {config.target_service}")
        print(f"   Geography: {config.geography}")
        print(f"   Detectors: {len(config.enabled_detectors)}")
        
        return built_analyzer
        
    except Exception as e:
        print(f"   ❌ Configuration error: {e}")
        return None
```

---

## 🔧 Configuration Examples

### Minimal Configuration

```python
# Simplest possible configuration
analyzer = (NetStealthAnalyzer.create()
    .with_logs("session.har")
    .build())
```

### Development Configuration

```python
# Configuration for development/testing
analyzer = (NetStealthAnalyzer.create()
    .with_logs("test_session.har")
    .for_service("localhost:3000")
    .with_detectors(["proxy", "browser"])
    .timeout(60)
    .enable_streaming()
    .track_progress(lambda c, t, m: print(f"{c}/{t}: {m}"))
    .build())
```

### Production Configuration

```python
# Configuration for production use
analyzer = (NetStealthAnalyzer.create()
    .with_log_directory("./logs", pattern="*.har", recursive=True)
    .for_service(["target1.com", "target2.com", "api.target.com"])
    .in_geography("US")
    .with_detectors("all")
    .max_concurrent_parsers(8)
    .memory_limit(1024)
    .timeout(1800)  # 30 minutes
    .output_formats("html", "json", "yaml")
    .output_to("./reports")
    .enable_fingerprint_analysis()
    .enable_session_timeline()
    .build())
```

### High-Performance Configuration

```python
# Configuration optimized for performance
analyzer = (NetStealthAnalyzer.create()
    .with_logs(large_file_list)
    .for_service(service_domains)
    .max_concurrent_parsers(16)
    .max_concurrent_detectors(8)
    .memory_limit(2048)
    .streaming_threshold(50)  # Stream files >50MB
    .enable_caching()
    .cache_size(500)
    .timeout(3600)  # 1 hour
    .build())
```

---

## 📚 Configuration Best Practices

### 1. Use Configuration Files for Complex Setups

```python
# Instead of long fluent API chains
analyzer = NetStealthAnalyzer.create().with_config_file("production.json").build()
```

### 2. Environment-Specific Configurations

```python
import os

config_file = f"config_{os.getenv('ENVIRONMENT', 'development')}.json"
analyzer = NetStealthAnalyzer.create().with_config_file(config_file).build()
```

### 3. Validate Configuration Early

```python
# Always validate before running analysis
analyzer = (NetStealthAnalyzer.create()
    .with_config_file("config.json")
    .validate()  # Catch errors early
    .build())
```

### 4. Use Appropriate Timeouts

```python
# Set timeouts based on expected file sizes
file_size_mb = os.path.getsize("session.har") / (1024 * 1024)
timeout = max(300, file_size_mb * 10)  # 10 seconds per MB, minimum 5 minutes

analyzer = analyzer.timeout(timeout)
```

### 5. Monitor Resource Usage

```python
# Set memory limits to prevent system issues
import psutil

available_memory = psutil.virtual_memory().available / (1024 * 1024)  # MB
memory_limit = min(1024, available_memory * 0.5)  # Use max 50% of available memory

analyzer = analyzer.memory_limit(memory_limit)
```

---

## 🔗 Related Documentation

- **[User Guide](USER_GUIDE.md)**: Basic usage and examples
- **[API Reference](API_REFERENCE.md)**: Complete API documentation
- **[Performance Guide](PERFORMANCE.md)**: Performance optimization
- **[Troubleshooting](TROUBLESHOOTING.md)**: Common issues and solutions

---

**NetStealth Analyzer v2.0 Configuration Guide** - Last Updated: September 18, 2025
