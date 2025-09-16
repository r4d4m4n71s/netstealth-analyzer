# NetStealth Analyzer

**Advanced log analyzer for network stealth operations** - Detects TLS fingerprint issues, proxy indicators, and security red flags that could compromise stealth operations.

---

## 🎯 What is NetStealth Analyzer?

NetStealth Analyzer is a comprehensive security analysis tool that examines logs from stealth network operations to identify potential vulnerabilities that could expose your activities. It acts as a "security health check" for your stealth operations.

### 🔍 What It Does
- **Analyzes your stealth operation logs** to find security issues
- **Detects proxy leaks** and automation signatures that could expose you
- **Validates TLS fingerprints** to ensure consistent encryption patterns
- **Provides actionable recommendations** to fix detected vulnerabilities

### 🛡️ Why You Need It
Stealth operations can fail due to subtle technical issues that are hard to spot manually. NetStealth Analyzer automatically identifies these problems before they compromise your operations.

---

## 🚀 Quick Start

### Installation
```bash
# Basic installation
pip install netstealth-analyzer

# Full features (recommended)
pip install netstealth-analyzer[full]
```

### Simple Analysis
```python
from netstealth_analyzer import NetStealthAnalyzer

# Analyze your logs
analyzer = NetStealthAnalyzer()
result = analyzer.analyze_single_file('logs/mitmproxy.log')

# Check results
print(f"Security Score: {result.summary.overall_score}/100")
print(f"Issues Found: {result.summary.total_issues_count}")
```

### Command Line Usage
```bash
# Analyze logs directory
netstealth-analyze logs/ --output report.json

# Quick analysis with summary
netstealth-analyze logs/session.log --format text
```

---

## 📊 What You Get

### Security Analysis Report
```
┌─────────────────────────────────────────────────────────────────┐
│                    SECURITY ANALYSIS REPORT                    │
├─────────────────────────────────────────────────────────────────┤
│ Overall Score: 85/100                                          │
│ Issues Found: 3 (1 High, 2 Medium)                            │
│ Analysis Confidence: 95%                                        │
└─────────────────────────────────────────────────────────────────┘

🚨 ISSUES DETECTED:
• TLS Fingerprint Mismatch (HIGH) - Inconsistent cipher suites
• Proxy Headers Exposed (MEDIUM) - X-Forwarded-For visible
• Automation Signatures (MEDIUM) - WebDriver patterns detected

💡 RECOMMENDATIONS:
• Configure consistent TLS settings across proxy chain
• Remove proxy headers from outbound requests
• Use stealth browser automation techniques
```

### Network Trace Visualization
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

---

## ⚙️ Configuration

### Basic Configuration
```python
from netstealth_analyzer import NetStealthAnalyzer, AnalysisConfig

# Simple configuration
config = AnalysisConfig(
    fingerprint_comparison=True,  # Enable TLS/browser fingerprint analysis
    auto_remediation=True,        # Generate fix suggestions
    session_timeline=True         # Timeline analysis
)

analyzer = NetStealthAnalyzer(config=config)
```

### Advanced Configuration for Specific Services
```python
from netstealth_analyzer.models import TargetGeography

# Configure for specific target geography
target_geography = TargetGeography(
    country_code="GB",
    country_name="United Kingdom", 
    ip_ranges=["203.0.113.0/24"],
    timezone="Europe/London",
    language="en-GB"
)

# Advanced configuration
config = AnalysisConfig(
    service_domains=[
        "mystore.com",
        "api.mystore.com", 
        "auth.mystore.com"
    ],
    target_geography=target_geography,
    fingerprint_comparison=True,  # TLS/browser fingerprint validation
    auto_remediation=True,        # Generate fix suggestions
    session_timeline=True         # Timeline analysis for consistency
)

analyzer = NetStealthAnalyzer(config=config)
```

---

## 🔍 Key Features Explained

### 1. **Fingerprint Comparison Analysis**

When `fingerprint_comparison=True` is enabled, the analyzer performs comprehensive security checks:

#### 🔐 TLS Fingerprint Analysis
- **TLS Version Consistency**: Ensures consistent TLS versions (1.2 vs 1.3) across requests
- **Cipher Suite Validation**: Detects inconsistent cipher suite usage that could reveal proxy chains
- **Certificate Chain Analysis**: Verifies certificate paths don't expose proxy infrastructure
- **Handshake Pattern Monitoring**: Analyzes timing patterns for automation signatures

#### 🌐 Browser Fingerprint Analysis
- **User-Agent Consistency**: Ensures User-Agent strings remain consistent throughout session
- **HTTP Header Validation**: Validates header patterns match expected browser behavior
- **Request Timing Analysis**: Detects automation patterns in request sequences
- **JavaScript Engine Detection**: Identifies browser automation tool signatures

#### 📊 Enhanced Detection Capabilities
- **TLS Fingerprint Mismatch**: Inconsistent cipher suites detected
- **Automation Signatures**: Selenium WebDriver patterns identified
- **Header Pattern Anomalies**: Non-standard header combinations found
- **Certificate Chain Exposure**: Proxy certificates visible in TLS chain

### 2. **Multi-Format Log Support**

| Format | Description | What It Detects |
|--------|-------------|-----------------|
| **mitmproxy** | Proxy server logs | Proxy leaks, header exposure |
| **HAR Files** | HTTP Archive format | Network patterns, timing issues |
| **Browser Console** | JavaScript console logs | Automation signatures, errors |
| **Execution Logs** | Custom operation logs | Workflow issues, failures |

### 3. **Intelligent Issue Detection**

The analyzer automatically detects:
- **Proxy Header Exposure**: Headers that reveal proxy usage
- **TLS Configuration Issues**: Inconsistent encryption settings
- **Automation Signatures**: Patterns that reveal automated tools
- **Geographic Inconsistencies**: IP locations that don't match targets
- **Timing Anomalies**: Request patterns that suggest automation

---

## 📋 Configuration Examples

### YAML Configuration File
```yaml
# analysis_config.yaml
fingerprint_comparison: true  # Enable comprehensive fingerprint analysis
session_timeline: true       # Enable timeline analysis
auto_remediation: true       # Generate fix suggestions

output_format: "json"
max_issues_per_category: 15

# Custom detection rules
detection_rules:
  - id: "custom_proxy_header"
    category: "proxy_detection"
    pattern: "X-Custom-Proxy"
    severity: "HIGH"
    description: "Custom proxy header detected"
```

### Python Configuration Examples

#### Basic Security Analysis
```python
config = AnalysisConfig(
    fingerprint_comparison=True  # Enables all fingerprint consistency checks
)
```

#### E-commerce Stealth Operations
```python
config = AnalysisConfig(
    service_domains=["shop.example.com", "api.example.com"],
    target_geography=target_geo,
    fingerprint_comparison=True,  # TLS/browser fingerprint validation
    auto_remediation=True,        # Generate fix suggestions for issues
    session_timeline=True         # Timeline analysis for consistency
)
```

#### High-Security Operations
```python
config = AnalysisConfig(
    service_domains=["secure.example.com"],
    fingerprint_comparison=True,
    auto_remediation=True,
    session_timeline=True,
    max_issues_per_category=50,   # Detailed analysis
    output_format="json"          # Structured output
)
```

---

## 🔧 Integration Examples

### With Network Stealth Libraries
```python
from netstealth import NetworkStealthSession
from netstealth_analyzer import NetStealthAnalyzer

# Run stealth operation with analysis
session = NetworkStealthSession(enable_analyzer=True)
# ... perform stealth operations ...

# Analyze session logs
analyzer = NetStealthAnalyzer()
result = analyzer.analyze(session.get_log_files())

# Check security score
if result.summary.overall_score < 80:
    print("⚠️ Security issues detected - review recommendations")
```

### Automated Security Monitoring
```python
import os
from pathlib import Path

def monitor_stealth_operations(logs_directory):
    """Monitor logs directory for new stealth operation logs."""
    analyzer = NetStealthAnalyzer(config=AnalysisConfig(
        fingerprint_comparison=True,
        auto_remediation=True
    ))
    
    for log_file in Path(logs_directory).glob("*.log"):
        result = analyzer.analyze_single_file(log_file)
        
        if result.summary.total_issues_count > 0:
            print(f"🚨 Issues found in {log_file.name}:")
            for issue in result.issues[:3]:  # Show top 3 issues
                print(f"  • {issue.title} ({issue.severity})")
```

---

## 📖 Advanced Usage

### Custom Detection Rules
```python
from netstealth_analyzer import DetectionRule, IssueCategory, SeverityLevel

# Define custom security rule
custom_rule = DetectionRule(
    id="custom_detection",
    category=IssueCategory.PROXY_DETECTION,
    pattern=r"your-custom-pattern",
    severity=SeverityLevel.HIGH,
    description="Custom detection rule for specific threats",
    recommendation="How to fix this specific issue"
)

# Use custom rule in analysis
config = AnalysisConfig(detection_rules=[custom_rule])
analyzer = NetStealthAnalyzer(config=config)
```

### Export and Reporting
```python
# Export detailed JSON report
analyzer.export_results(result, 'security_report.json', format_type='json')

# Export readable text summary  
analyzer.export_results(result, 'summary.txt', format_type='text')

# Export HTML report with visualizations
analyzer.export_results(result, 'report.html', format_type='html')
```

---

## 🛠️ Development & Contributing

### Development Setup
```bash
git clone https://github.com/netstealth/netstealth-analyzer.git
cd netstealth-analyzer
pip install -e .[dev]

# Run tests
pytest

# Run with coverage
pytest --cov=netstealth-analyzer
```

### Contributing
We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details on:
- Code style and standards
- Testing requirements
- Pull request process
- Issue reporting

---

## 📚 Resources & Support

### Documentation & Help
- 📖 [Full Documentation](https://netstealth-analyzer.readthedocs.io/)
- 🐛 [Issue Tracker](https://github.com/netstealth/netstealth-analyzer/issues)
- 💬 [Community Discussions](https://github.com/netstealth/netstealth-analyzer/discussions)
- 📧 [Security Issues](mailto:security@netstealth.org)

### License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**🔒 Part of the NetStealth Ecosystem** - Enhancing stealth operations through comprehensive security analysis and vulnerability detection.

*Protect your stealth operations with automated security analysis.*
