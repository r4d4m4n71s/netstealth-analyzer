# NetStealth Analyzer

Advanced log analyzer for network stealth operations - detects TLS fingerprint issues, proxy indicators, and security red flags that could compromise stealth operations.

## Overview

The NetStealth Analyzer is a comprehensive library designed to analyze logs from stealth operations and detect potential issues that could reveal proxy usage, automation, or other indicators that might compromise stealth activities. It's specifically designed as a complement to network stealth libraries.

## Features

### 🔍 **Comprehensive Log Analysis**
- **Multi-format support**: mitmproxy, HAR files, browser console logs, execution logs
- **Real-time parsing**: Process logs from active stealth sessions
- **Pattern recognition**: Advanced regex and heuristic-based detection

### 🛡️ **Security Issue Detection**
- **TLS Fingerprint Analysis**: Detect inconsistent TLS configurations
- **Proxy Header Exposure**: Find proxy indicators in HTTP headers
- **Browser Configuration Issues**: Identify automation signatures
- **Network Anomalies**: Spot unusual traffic patterns

### 📊 **Advanced Reporting**
- **Risk Assessment**: Score-based evaluation of stealth effectiveness
- **Network Trace Mapping**: Visualize complete proxy chains
- **Performance Metrics**: Analyze response times and success rates
- **Auto-remediation**: Generate fix suggestions for detected issues

### 🔧 **Flexible Configuration**
- **Custom Detection Rules**: Define your own detection patterns
- **Output Formats**: JSON, YAML, text, and HTML reports
- **Integration Ready**: Easy integration with existing workflows

## Installation

### Basic Installation
```bash
pip install netstealth-analyzer
```

### With Full Analysis Features
```bash
pip install netstealth-analyzer[full]
```

### Development Installation
```bash
pip install netstealth-analyzer[dev]
```

## Quick Start

### Basic Usage
```python
from netstealth_analyzer import NetStealthAnalyzer

# Initialize analyzer with default configuration
analyzer = NetStealthAnalyzer()

# Analyze single log file
result = analyzer.analyze_single_file('logs/mitmproxy.log')

# Print summary
print(f"Analysis Score: {result.summary.overall_score}/100")
print(f"Issues Found: {result.summary.total_issues_count}")
```

### Configurable Service Patterns & Geography
```python
from netstealth_analyzer import NetStealthAnalyzer
from netstealth_analyzer.models import AnalysisConfig, TargetGeography

# Configure for specific service and geography
target_geography = TargetGeography(
    country_code="GB",
    country_name="United Kingdom", 
    ip_ranges=["203.0.113.0/24"],
    timezone="Europe/London",
    language="en-GB"
)

config = AnalysisConfig(
    service_domains=[
        "mystore.com",
        "api.mystore.com", 
        "auth.mystore.com"
    ],
    target_geography=target_geography,
    auto_remediation=True,
    fingerprint_comparison=True
)

analyzer = NetStealthAnalyzer(config=config)

# Analyze multiple sources
result = analyzer.analyze([
    'logs/mitmproxy.log',
    'logs/browser_console.log', 
    'logs/execution.log'
])
```

## Analysis Results

The analyzer provides comprehensive results including:

### Network Trace Example
```
┌─────────────┬──────────────┬─────────────┬──────────────┬─────────────┬────────────────┬─────────────────┐
│ Hop         │ Actor        │ Incoming IP │ Outgoing IP  │ Actor Name  │ TLS Info       │ Detection Risk  │
├─────────────┼──────────────┼─────────────┼──────────────┼─────────────┼────────────────┼─────────────────┤
│ 1           │ Client       │ [local]     │ 127.0.0.1    │ Browser     │ TLS 1.3        │ ✅ Safe         │
│ 2           │ Local Proxy  │ 127.0.0.1   │ 10.0.0.1     │ mitmproxy   │ TLS 1.2        │ ⚠️ Medium       │
│ 3           │ Proxy Chain  │ 10.0.0.1    │ 203.45.x.x   │ GeoProxy    │ Standard       │ ⚠️ Medium       │
│ 4           │ Exit Node    │ 186.84.x.x  │ External     │ Colombia    │ Standard       │ ✅ Safe         │
│ 5           │ Target       │ External    │ -            │ Target API  │ Standard       │ -               │
└─────────────┴──────────────┴─────────────┴──────────────┴─────────────┴────────────────┴─────────────────┘
```

### Issue Detection Example
- **TLS Fingerprint Mismatch**: Detected inconsistent cipher suite usage
- **Proxy Headers Exposed**: X-Forwarded-For headers visible in 3 requests  
- **Automation Signatures**: Selenium WebDriver patterns detected
- **Geographic Inconsistency**: IP geolocation doesn't match expected region

## Integration with Network Stealth Libraries

The analyzer can optionally integrate with network stealth libraries:

```python
from netstealth import NetworkStealthSession
from netstealth_analyzer import NetStealthAnalyzer

# Optional analysis after stealth session
session = NetworkStealthSession(enable_analyzer=True)
# ... perform stealth operations ...

# Analyze session logs
analyzer = NetStealthAnalyzer()
result = analyzer.analyze(session.get_log_files())
```

## Command Line Usage

```bash
# Analyze single file
netstealth-analyze logs/mitmproxy_debug.log

# Multiple sources with output
netstealth-analyze logs/ --output analysis_report.json --format json

# Custom configuration
netstealth-analyze logs/ --config custom_config.yaml --verbose
```

## Configuration

```yaml
# analysis_config.yaml
fingerprint_comparison: true
session_timeline: true
auto_remediation: true

output_format: "json"
max_issues_per_category: 15

detection_rules:
  - id: "custom_proxy_header"
    category: "proxy_detection"
    pattern: "X-Custom-Proxy"
    severity: "HIGH"
    description: "Custom proxy header detected"
```

## Supported Log Formats

| Format | Description | Auto-Detection |
|--------|-------------|----------------|
| **mitmproxy** | mitmproxy debug and access logs | ✅ |
| **HAR** | HTTP Archive files (.har) | ✅ |
| **Browser Console** | Chrome/Firefox console logs | ✅ |
| **Execution Logs** | Custom POC execution logs | ✅ |

## Advanced Features

### Custom Detection Rules
```python
from netstealth_analyzer import DetectionRule, IssueCategory, SeverityLevel

custom_rule = DetectionRule(
    id="custom_detection",
    category=IssueCategory.PROXY_DETECTION,
    pattern=r"your-custom-pattern",
    severity=SeverityLevel.HIGH,
    description="Custom detection rule",
    recommendation="How to fix this issue"
)

config = AnalysisConfig(detection_rules=[custom_rule])
analyzer = NetStealthAnalyzer(config=config)
```

### Export Options
```python
# Export detailed JSON report
analyzer.export_results(result, 'detailed_report.json', format_type='json')

# Export readable text summary  
analyzer.export_results(result, 'summary.txt', format_type='text')
```

## Development

```bash
git clone https://github.com/netstealth/netstealth-analyzer.git
cd netstealth-analyzer
pip install -e .[dev]

# Run tests
pytest

# Run with coverage
pytest --cov=netstealth-analyzer
```

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- 📖 [Documentation](https://netstealth-analyzer.readthedocs.io/)
- 🐛 [Issue Tracker](https://github.com/netstealth/netstealth-analyzer/issues)
- 💬 [Discussions](https://github.com/netstealth/netstealth-analyzer/discussions)

---

**Part of the NetStealth ecosystem** - Enhancing stealth operations through comprehensive log analysis and issue detection.
