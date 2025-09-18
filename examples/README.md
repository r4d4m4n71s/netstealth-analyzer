# 📚 NetStealth Analyzer Examples

**Practical Examples and Use Cases**

This directory contains comprehensive examples demonstrating how to use NetStealth Analyzer for various security analysis scenarios.

---

## 📁 Directory Structure

```
examples/
├── README.md                    # This file
├── basic_usage/                 # Simple examples for beginners
│   ├── simple_analysis.py      # Basic HAR file analysis
│   ├── multiple_files.py       # Analyzing multiple log files
│   └── streaming_analysis.py   # Real-time streaming analysis
├── advanced_workflows/          # Complex analysis scenarios
│   ├── proxy_audit.py          # Comprehensive proxy security audit
│   ├── automation_detection.py # Browser automation detection
│   ├── geographic_analysis.py  # Geographic consistency checking
│   └── security_assessment.py  # Complete security assessment
├── integrations/               # Integration examples
│   ├── ci_cd_integration.py   # CI/CD pipeline integration
│   ├── monitoring_system.py   # Monitoring system integration
│   └── api_integration.py     # REST API integration
├── custom_detectors/           # Custom detector examples
│   ├── custom_proxy_detector.py    # Custom proxy detection logic
│   ├── custom_browser_detector.py  # Custom browser detection
│   └── plugin_development.py       # Plugin development example
├── performance/                # Performance optimization examples
│   ├── large_file_processing.py    # Handling large files efficiently
│   ├── concurrent_analysis.py      # Parallel processing
│   └── memory_optimization.py      # Memory-efficient analysis
├── sample_data/               # Sample log files for testing
│   ├── sample_session.har     # Sample HAR file
│   ├── sample_proxy.log       # Sample mitmproxy log
│   ├── sample_browser.log     # Sample browser automation log
│   └── README.md              # Sample data documentation
└── notebooks/                 # Jupyter notebook examples
    ├── interactive_analysis.ipynb      # Interactive analysis tutorial
    ├── visualization_examples.ipynb    # Data visualization examples
    └── research_workflows.ipynb        # Research and analysis workflows
```

---

## 🚀 Quick Start Examples

### Basic Analysis

```python
# examples/basic_usage/simple_analysis.py
import asyncio
from netstealth_analyzer import NetStealthAnalyzer

async def main():
    analyzer = (NetStealthAnalyzer.create()
                .with_logs("examples/sample_data/sample_session.har")
                .for_service("example.com")
                .build())
    
    result = await analyzer.analyze()
    print(f"Analysis Score: {result.summary.overall_score}/100")
    print(f"Issues Found: {len(result.issues)}")

asyncio.run(main())
```

### Advanced Workflow

```python
# examples/advanced_workflows/proxy_audit.py
import asyncio
from netstealth_analyzer import NetStealthAnalyzer
from netstealth_analyzer.core.events import AnalysisEvent

async def proxy_security_audit():
    analyzer = (NetStealthAnalyzer.create()
                .with_logs([
                    "proxy_session.har",
                    "mitmproxy_debug.log"
                ])
                .for_service("target-service.com")
                .with_detectors(["proxy", "network"])
                .build())
    
    result = await analyzer.analyze()
    
    # Generate comprehensive audit report
    proxy_issues = [issue for issue in result.issues 
                   if 'proxy' in issue.category.value.lower()]
    
    print(f"🔍 Proxy Security Audit Results:")
    print(f"   Total Issues: {len(result.issues)}")
    print(f"   Proxy Issues: {len(proxy_issues)}")
    
    return result

asyncio.run(proxy_security_audit())
```

---

## 📖 Example Categories

### 🎯 Basic Usage Examples

Perfect for beginners learning NetStealth Analyzer:

- **Simple Analysis**: Basic HAR file analysis
- **Multiple Files**: Analyzing different log formats together
- **Streaming Analysis**: Real-time processing for large files
- **Event Handling**: Progress tracking and event monitoring

### 🔧 Advanced Workflows

Complex real-world scenarios:

- **Proxy Security Audit**: Comprehensive proxy configuration analysis
- **Automation Detection**: Detecting browser automation and evasion
- **Geographic Analysis**: Location consistency verification
- **Security Assessment**: Complete security posture evaluation

### 🔗 Integration Examples

Integrating NetStealth Analyzer with other systems:

- **CI/CD Integration**: Automated security testing in pipelines
- **Monitoring Systems**: Real-time security monitoring
- **API Integration**: REST API for web applications
- **Database Integration**: Storing and querying analysis results

### 🎨 Custom Development

Extending NetStealth Analyzer:

- **Custom Detectors**: Building specialized detection logic
- **Plugin Development**: Creating reusable plugins
- **Custom Parsers**: Supporting new log formats
- **Custom Reports**: Generating specialized reports

### ⚡ Performance Examples

Optimizing for different scenarios:

- **Large File Processing**: Efficient handling of GB-sized files
- **Concurrent Analysis**: Parallel processing multiple files
- **Memory Optimization**: Memory-efficient streaming analysis
- **Resource Management**: CPU and memory usage optimization

---

## 🧪 Sample Data

The `sample_data/` directory contains realistic sample files for testing:

- **sample_session.har**: Browser session with various requests
- **sample_proxy.log**: Mitmproxy debug log with proxy flows
- **sample_browser.log**: Browser automation detection scenarios
- **sample_large.har**: Large file for performance testing

All sample data is anonymized and safe for testing purposes.

---

## 📓 Jupyter Notebooks

Interactive examples for exploration and learning:

- **Interactive Analysis**: Step-by-step analysis tutorial
- **Visualization Examples**: Charts and graphs for analysis results
- **Research Workflows**: Advanced analysis techniques for researchers

---

## 🏃‍♂️ Running Examples

### Prerequisites

```bash
# Install NetStealth Analyzer
cd netstealth-analyzer
poetry install

# Or with pip
pip install -e .
```

### Running Basic Examples

```bash
# Navigate to examples directory
cd examples

# Run basic analysis
python basic_usage/simple_analysis.py

# Run advanced workflow
python advanced_workflows/proxy_audit.py
```

### Running Jupyter Notebooks

```bash
# Install Jupyter
pip install jupyter

# Start Jupyter server
jupyter notebook notebooks/

# Open interactive_analysis.ipynb
```

---

## 🎓 Learning Path

### Beginner Path

1. **Start with Basic Examples**:
   - `basic_usage/simple_analysis.py`
   - `basic_usage/multiple_files.py`

2. **Learn Event Handling**:
   - `basic_usage/streaming_analysis.py`

3. **Try Sample Data**:
   - Use provided sample files
   - Understand different log formats

### Intermediate Path

1. **Advanced Workflows**:
   - `advanced_workflows/proxy_audit.py`
   - `advanced_workflows/automation_detection.py`

2. **Performance Optimization**:
   - `performance/large_file_processing.py`
   - `performance/concurrent_analysis.py`

3. **Integration Examples**:
   - `integrations/ci_cd_integration.py`

### Advanced Path

1. **Custom Development**:
   - `custom_detectors/custom_proxy_detector.py`
   - `custom_detectors/plugin_development.py`

2. **Research Workflows**:
   - `notebooks/research_workflows.ipynb`

3. **Production Deployment**:
   - `integrations/monitoring_system.py`
   - `integrations/api_integration.py`

---

## 🤝 Contributing Examples

We welcome contributions of new examples! Please follow these guidelines:

### Example Structure

```python
#!/usr/bin/env python3
"""
NetStealth Analyzer Example: [Title]

Description: [Brief description of what this example demonstrates]

Requirements:
- NetStealth Analyzer v2.0+
- [Any additional requirements]

Usage:
    python example_name.py
"""

import asyncio
from netstealth_analyzer import NetStealthAnalyzer

async def main():
    """Main example function."""
    # Your example code here
    pass

if __name__ == "__main__":
    asyncio.run(main())
```

### Documentation Requirements

- Clear docstring explaining the example
- Comments explaining key concepts
- Error handling for common issues
- Sample output or expected results

### Submission Process

1. Create example in appropriate directory
2. Add documentation and comments
3. Test with sample data
4. Submit pull request with description

---

## 📞 Support

- **GitHub Issues**: [Report problems with examples](https://github.com/r4d4m4n71s/netstealth-analyzer/issues)
- **Discussions**: [Ask questions about examples](https://github.com/r4d4m4n71s/netstealth-analyzer/discussions)
- **Documentation**: [Full documentation](../docs/)

---

## 🔗 Related Documentation

- **[User Guide](../docs/USER_GUIDE.md)**: Complete usage guide
- **[Configuration Guide](../docs/CONFIGURATION.md)**: Configuration reference
- **[API Reference](../docs/API_REFERENCE.md)**: Complete API documentation
- **[Troubleshooting](../docs/TROUBLESHOOTING.md)**: Common issues and solutions

---

**NetStealth Analyzer Examples** - Last Updated: September 18, 2025
