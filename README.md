# 🛡️ NetStealth Analyzer v2.0

[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-96%2F96%20passing-brightgreen.svg)](https://github.com/r4d4m4n71s/netstealth-analyzer)
[![Coverage](https://img.shields.io/badge/coverage-95%25-brightgreen.svg)](https://github.com/r4d4m4n71s/netstealth-analyzer)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Advanced Network Stealth Analysis & Proxy Detection Framework**

NetStealth Analyzer is a comprehensive, async-first framework for analyzing network traffic, detecting proxy usage, and identifying stealth-related security issues. Built with Python 3.13+ and modern async patterns.

## 🚀 Key Features

### 🔍 **Multi-Format Log Parsing**
- **HAR Files**: Complete HTTP Archive analysis with timing data
- **Mitmproxy Logs**: Debug log parsing with request/response correlation
- **Browser Logs**: Selenium/automation detection
- **POC Results**: Custom proof-of-concept integration

### 🕵️ **Advanced Detection Capabilities**
- **Proxy Detection**: Headers, IP leaks, WebRTC, datacenter IPs
- **Browser Automation**: Selenium, headless browser detection
- **Network Anomalies**: Routing analysis, geographic inconsistencies
- **TLS Analysis**: Certificate validation, handshake patterns

### ⚡ **Modern Architecture**
- **Async-First**: Full asyncio support for high performance
- **Event-Driven**: Real-time progress tracking and notifications
- **Plugin System**: Extensible with custom detectors and parsers
- **Streaming**: Process large files without memory issues

## 📊 Current Status

- **Project Completion**: 95%
- **Test Coverage**: 95% overall, 99% core components
- **Test Results**: 96/96 major component tests passing (100%)
- **Python Version**: 3.13.7 compatible
- **Architecture**: Production-ready

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    NetStealth Analyzer v2.0                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Input Layer    →    Analysis Core    →    Output Layer        │
│  ┌─────────────┐    ┌─────────────────┐    ┌─────────────────┐ │
│  │ • HAR Files │    │ • Pipeline Eng. │    │ • JSON Reports  │ │
│  │ • Mitmproxy │    │ • Event Bus     │    │ • HTML Reports  │ │
│  │ • Browser   │    │ • Detectors     │    │ • Markdown      │ │
│  │ • POC Data  │    │ • Analyzers     │    │ • YAML Reports  │ │
│  └─────────────┘    └─────────────────┘    └─────────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/r4d4m4n71s/netstealth-analyzer.git
cd netstealth-analyzer

# Install with Poetry (recommended)
poetry install

# Or with pip
pip install -e .
```

### Basic Usage

```python
import asyncio
from netstealth_analyzer import NetStealthAnalyzer

async def analyze_session():
    # Create analyzer with fluent API
    analyzer = (NetStealthAnalyzer.create()
                .with_logs("session.har")
                .for_service("example.com")
                .track_progress(lambda event, data: print(f"Progress: {data}"))
                .build())
    
    # Run analysis
    result = await analyzer.analyze()
    
    # Generate report
    await analyzer.report(result, format="html", output="report.html")

# Run analysis
asyncio.run(analyze_session())
```

### Advanced Usage

```python
import asyncio
from netstealth_analyzer import NetStealthAnalyzer
from netstealth_analyzer.core.events import AnalysisEvent

async def advanced_analysis():
    analyzer = NetStealthAnalyzer.create()
    
    # Configure multiple log sources
    analyzer.with_logs([
        "session.har",
        "mitmproxy.log",
        "browser_automation.log"
    ])
    
    # Set service domains for analysis
    analyzer.for_service(["example.com", "api.service.com"])
    
    # Configure detectors
    analyzer.with_detectors([
        "proxy", "browser", "network", "tls"
    ])
    
    # Add event handlers
    async def on_issue_found(event, data):
        print(f"🚨 Issue found: {data.title} (Severity: {data.severity})")
    
    analyzer.on_event(AnalysisEvent.ISSUE_FOUND, on_issue_found)
    
    # Build and analyze
    built_analyzer = analyzer.build()
    result = await built_analyzer.analyze()
    
    # Stream results to multiple formats
    await built_analyzer.report(result, [
        {"format": "json", "output": "results.json"},
        {"format": "html", "output": "report.html"},
        {"format": "markdown", "output": "summary.md"}
    ])

asyncio.run(advanced_analysis())
```

## 🧪 Testing

The project has comprehensive test coverage across all major components:

```bash
# Run all tests
poetry run pytest

# Run with coverage
poetry run pytest --cov=src/netstealth_analyzer --cov-report=html

# Run specific component tests
poetry run pytest tests/unit/test_detectors_browser.py -v
poetry run pytest tests/unit/test_parsers_har.py -v
```

### Test Results Summary
- **Browser Detector**: 16/16 tests passing (100%)
- **Network Detector**: 13/13 tests passing (100%)
- **Proxy Detector**: 18/18 tests passing (100%)
- **HAR Parser**: 28/28 tests passing (100%)
- **Mitmproxy Parser**: 21/21 tests passing (100%)
- **Total**: 96/96 tests passing (100%)

## 📚 Documentation

### Core Components

#### Parsers
- **HAR Parser**: Extracts HTTP requests, responses, and timing data from HAR files
- **Mitmproxy Parser**: Parses mitmproxy debug logs with request/response correlation
- **Browser Parser**: Analyzes browser automation logs
- **POC Parser**: Custom proof-of-concept data integration

#### Detectors
- **Proxy Detector**: Identifies proxy usage through headers, IP analysis, and behavioral patterns
- **Browser Detector**: Detects automation tools like Selenium, headless browsers
- **Network Detector**: Analyzes routing patterns, geographic inconsistencies
- **TLS Detector**: Examines TLS handshakes and certificate patterns

#### Models
- **NetworkTrace**: Core model for network routing analysis
- **NetworkHop**: Individual routing points with connection details
- **HttpRequest/HttpResponse**: HTTP-specific data models
- **Issue**: Security issue representation with evidence

### API Reference

#### Fluent API
```python
NetStealthAnalyzer.create()
    .with_logs(files)           # Add log files
    .for_service(domains)       # Set target domains
    .with_detectors(types)      # Configure detectors
    .track_progress(callback)   # Progress tracking
    .on_event(event, handler)   # Event handling
    .build()                    # Create analyzer
```

#### Core Methods
```python
await analyzer.analyze()                    # Run analysis
await analyzer.stream_analyze()             # Stream processing
await analyzer.report(result, format)      # Generate reports
```

## 🔧 Development

### Project Structure
```
src/netstealth_analyzer/
├── core/           # Core framework (events, pipeline, interfaces)
├── models/         # Data models and enums
├── parsers/        # Log file parsers
├── detectors/      # Security detectors
├── reporting/      # Report generation
├── plugins/        # Plugin system
└── utils/          # Utilities
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Run the test suite
5. Submit a pull request

### Code Quality

```bash
# Format code
poetry run black src/ tests/

# Lint code
poetry run ruff check src/ tests/

# Type checking
poetry run mypy src/
```

## 🎯 Roadmap

### Completed ✅
- [x] Core framework and async architecture
- [x] All major parsers (HAR, Mitmproxy, Browser)
- [x] All major detectors (Proxy, Browser, Network, TLS)
- [x] Comprehensive test suite (95% coverage)
- [x] Event-driven architecture
- [x] Plugin system
- [x] Multiple report formats

### In Progress 🚧
- [ ] API documentation generation
- [ ] Performance benchmarking
- [ ] Migration guide from v1.0

### Planned 📋
- [ ] Web UI dashboard
- [ ] Real-time monitoring
- [ ] Machine learning detection models
- [ ] Cloud deployment options

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Support

- **GitHub Issues**: [Report bugs or request features](https://github.com/r4d4m4n71s/netstealth-analyzer/issues)
- **Documentation**: [Full documentation](https://github.com/r4d4m4n71s/netstealth-analyzer/wiki)
- **Discussions**: [Community discussions](https://github.com/r4d4m4n71s/netstealth-analyzer/discussions)

## 🏆 Acknowledgments

- Built with modern Python 3.13+ features
- Powered by asyncio for high performance
- Uses Pydantic v2 for data validation
- Comprehensive testing with pytest

---

**NetStealth Analyzer v2.0** - Advanced Network Stealth Analysis Framework
