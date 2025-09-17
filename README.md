# NetStealth Analyzer v2.0

**Advanced log analyzer for network stealth operations with async support and plugin system**

## Overview

NetStealth Analyzer v2.0 is a complete refactor of the network stealth analysis tool, designed from the ground up for Python 3.13+ with modern async/await patterns, event-driven architecture, and a powerful plugin system.

## Features

- **Python 3.13+ Optimized**: Leverages the latest Python features for optimal performance
- **Async-First Architecture**: Full async/await implementation for I/O operations and concurrent processing
- **Event-Driven System**: Real-time progress tracking and notifications via EventBus
- **Plugin System**: Dynamic loading with sandboxing and registry management
- **Multiple Input Formats**: HAR files, Mitmproxy logs, browser console logs, and POC execution logs
- **Flexible Reporting**: JSON, Markdown, HTML, and YAML output formats
- **Fluent API**: Intuitive builder pattern for configuration
- **Comprehensive Analysis**: TLS fingerprinting, proxy leak detection, browser configuration analysis

## Requirements

- Python 3.13+
- Poetry for dependency management

## Installation

```bash
# Clone the repository
git clone https://github.com/r4d4m4n71s/netstealth-analyzer.git
cd netstealth-analyzer

# Install dependencies
poetry install

# Activate the virtual environment
poetry shell
```

## Quick Start

```python
from netstealth_analyzer import NetStealthAnalyzer

# Simple analysis
analyzer = (
    NetStealthAnalyzer.create()
        .with_logs("session.har", "mitmproxy.log")
        .for_service("example.com")
        .track_progress(progress_callback)
        .build()
)

result = await analyzer.analyze()
```

## Advanced Usage

```python
# Advanced configuration
analyzer = (
    NetStealthAnalyzer.create()
        .with_logs("logs/session.har", "logs/mitmproxy.log")
        .for_service("mystore.com")
        .in_geography("US")
        .enable_fingerprint_analysis()
        .with_plugin(CustomDetector())
        .track_events(event_handler)
        .build()
)

# Streaming results
async for issue in analyzer.stream_issues():
    print(f"Found: {issue.title}")
```

## Plugin Development

```python
class CustomAPIDetector(IDetectorPlugin):
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="custom_api_detector",
            version="1.0.0",
            type=PluginType.DETECTOR
        )
    
    async def detect(self, context: Dict[str, Any]) -> List[Issue]:
        # Custom detection logic
        return issues
```

## Development

```bash
# Run tests
poetry run pytest

# Format code
poetry run black src/ tests/
poetry run ruff check src/ tests/

# Type checking
poetry run mypy src/
```

## Architecture

- **Core**: Main analyzer, pipeline, events system
- **Models**: Data structures for issues, network traces, results
- **Parsers**: Log file parsing for different formats
- **Detectors**: Issue detection algorithms
- **Reporting**: Multi-format report generation
- **Plugins**: Extensible plugin architecture

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License. See LICENSE file for details.

## Changelog

### v2.0.0
- Complete refactor for Python 3.13+
- Async-first architecture
- Event-driven system
- Plugin architecture
- Multiple report formats
- Fluent API design
