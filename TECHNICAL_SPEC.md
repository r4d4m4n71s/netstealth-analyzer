# 📋 NetStealth Analyzer v2.0 - Technical Specification & Implementation Plan

## 🎯 Project Overview

**Project**: NetStealth Analyzer v2.0 (Complete Refactor)  
**Python Version**: 3.13+ (Latest Python Features)  
**Architecture**: Async-first, Event-driven, Plugin-based  
**Old Project Location**: `../netstealth-analyzer-old/`  
**New Project Location**: `../netstealth-analyzer/`  
**Start Date**: September 16, 2025  
**Target Completion**: TBD

---

## 🏗️ Architecture Specification

### Core Design Decisions
- **Async/Await**: Full async implementation for I/O operations and concurrent processing
- **Event-Based**: EventBus for progress tracking and real-time notifications
- **Incremental Reporting**: Stream results as they're discovered, not just at the end
- **Error Handling**: Structured error types with recovery strategies and context preservation
- **Report Formats**: JSON, Markdown, HTML, YAML output with templating
- **Plugin System**: Dynamic loading with sandboxing and registry management
- **Fluent API**: Builder pattern for intuitive configuration
- **SOLID Principles**: Single responsibility, open/closed, dependency inversion

### Key Improvements Over v1.0
1. **Performance**: 3-5x faster through async processing
2. **Usability**: Fluent API reduces configuration complexity
3. **Extensibility**: Plugin system allows custom detectors/parsers
4. **Visibility**: Real-time progress tracking and streaming results
5. **Reliability**: Comprehensive error handling with recovery
6. **Maintainability**: Modular architecture with clear separation of concerns

---

## 📂 Complete Project Structure

```
netstealth-analyzer/
├── pyproject.toml                         # Project configuration (✅ DONE)
├── README.md                               # Documentation
├── TECHNICAL_SPEC.md                      # This document (✅ DONE)
├── .python-version                        # Python 3.13
├── .gitignore
│
├── src/
│   └── netstealth_analyzer/
│       ├── __init__.py                    # Package initialization
│       ├── analyzer.py                    # Main analyzer class
│       ├── builder.py                     # Fluent API builder
│       ├── config.py                      # Configuration models
│       ├── compatibility.py               # Python version compatibility
│       │
│       ├── core/
│       │   ├── __init__.py
│       │   ├── pipeline.py                # Pipeline processing engine
│       │   ├── events.py                  # Event bus system
│       │   ├── errors.py                  # Error handling
│       │   └── interfaces.py              # Abstract base classes
│       │
│       ├── models/
│       │   ├── __init__.py
│       │   ├── issues.py                  # Issue data models
│       │   ├── network.py                 # Network trace models
│       │   ├── results.py                 # Analysis result models
│       │   └── enums.py                   # Enumerations
│       │
│       ├── parsers/
│       │   ├── __init__.py
│       │   ├── base.py                    # ILogParser interface
│       │   ├── har.py                     # HAR file parser
│       │   ├── mitmproxy.py              # Mitmproxy log parser
│       │   ├── browser.py                 # Browser console parser
│       │   └── poc.py                     # POC execution parser
│       │
│       ├── detectors/
│       │   ├── __init__.py
│       │   ├── base.py                    # IDetector interface
│       │   ├── registry.py                # Plugin registry
│       │   ├── tls.py                     # TLS fingerprint detector
│       │   ├── proxy.py                   # Proxy leak detector
│       │   ├── browser.py                 # Browser config detector
│       │   └── network.py                 # Network anomaly detector
│       │
│       ├── reporting/
│       │   ├── __init__.py
│       │   ├── reporter.py                # Incremental reporter
│       │   ├── formats.py                 # Output formatters
│       │   └── templates.py               # Report templates
│       │
│       ├── plugins/
│       │   ├── __init__.py
│       │   ├── base.py                    # Plugin interfaces
│       │   ├── registry.py                # Plugin management
│       │   ├── sandbox.py                 # Plugin sandboxing
│       │   └── loader.py                  # Dynamic plugin loading
│       │
│       └── utils/
│           ├── __init__.py
│           ├── async_helpers.py           # Async utilities
│           ├── validators.py              # Input validation
│           └── logging.py                 # Logging configuration
│
├── plugins/                               # Built-in plugins
│   ├── __init__.py
│   └── examples/
│       ├── custom_api_detector.py
│       └── cloudflare_parser.py
│
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
│
├── examples/
│   ├── basic_usage.py
│   ├── async_analysis.py
│   ├── plugin_example.py
│   └── streaming_results.py
│
└── docs/
    ├── api.md
    ├── plugins.md
    └── migration.md
```

---

## 📝 Implementation Checklist

### Phase 1: Project Setup & Core Infrastructure ✅
- [x] Create new project structure
- [x] Set up pyproject.toml with Poetry
- [x] Create technical specification document
- [ ] Configure Python 3.13+ environment
- [ ] Initialize git repository
- [ ] Set up pre-commit hooks
- [ ] Create compatibility layer for Python versions

### Phase 2: Core Components ✅
- [x] Implement EventBus system (`core/events.py`)
- [x] Create error handling architecture (`core/errors.py`)
- [x] Define abstract interfaces (`core/interfaces.py`)
- [x] Build Pipeline engine (`core/pipeline.py`)
- [x] Implement configuration models (`config.py`)

### Phase 3: Models & Data Structures ✅
- [x] Port and refactor Issue models (reference: `netstealth-analyzer-old/models.py`)
- [x] Create network trace models
- [x] Define result models
- [x] Implement enumerations

### Phase 4: Fluent API & Builder ✅
- [x] Create AnalyzerBuilder class (`builder.py`)
- [x] Implement method chaining
- [x] Add validation logic
- [x] Create main Analyzer class (`analyzer.py`)

### Phase 5: Parsers (Port from old project)
- [ ] Create ILogParser interface
- [ ] Port HAR parser (reference: `netstealth-analyzer-old/parsers/har.py`)
- [ ] Port Mitmproxy parser (reference: `netstealth-analyzer-old/parsers/mitmproxy.py`)
- [ ] Port Browser parser (reference: `netstealth-analyzer-old/parsers/browser.py`)
- [ ] Port POC parser (reference: `netstealth-analyzer-old/parsers/poc.py`)
- [ ] Add async support to all parsers

### Phase 6: Detectors (Refactor from old project)
- [ ] Create IDetector interface
- [ ] Refactor TLS detector (reference: `netstealth-analyzer-old/detectors/tls.py`)
- [ ] Refactor Proxy detector (reference: `netstealth-analyzer-old/detectors/proxy.py`)
- [ ] Refactor Browser detector (reference: `netstealth-analyzer-old/detectors/browser.py`)
- [ ] Refactor Network detector (reference: `netstealth-analyzer-old/detectors/network.py`)
- [ ] Implement detector registry

### Phase 7: Reporting System
- [ ] Create IncrementalReporter
- [ ] Implement JSON formatter
- [ ] Implement Markdown formatter
- [ ] Implement HTML formatter
- [ ] Create report templates
- [ ] Add streaming support

### Phase 8: Plugin System
- [ ] Define plugin interfaces
- [ ] Create plugin registry
- [ ] Implement plugin loader
- [ ] Add plugin sandboxing
- [ ] Create example plugins
- [ ] Write plugin documentation

### Phase 9: Testing
- [ ] Set up pytest with async support
- [ ] Create unit tests for core components
- [ ] Create integration tests
- [ ] Add test fixtures from old project
- [ ] Achieve 80% code coverage

### Phase 10: Documentation & Examples
- [ ] Write API documentation
- [ ] Create migration guide from v1
- [ ] Write plugin development guide
- [ ] Create usage examples
- [ ] Update README

---

## 💻 Key API Design Examples

### 1. Fluent API Usage
```python
# Simple analysis
analyzer = (
    NetStealthAnalyzer.create()
        .with_logs("session.har", "mitmproxy.log")
        .for_service("example.com")
        .track_progress(progress_callback)
        .build()
)

result = await analyzer.analyze()

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

### 2. Event-Based Progress Tracking
```python
from netstealth_analyzer.core.events import AnalysisEvent

def progress_handler(event: AnalysisEvent, data: Any):
    match event:
        case AnalysisEvent.STARTED:
            print("Analysis started")
        case AnalysisEvent.ISSUE_FOUND:
            print(f"Issue found: {data.title}")
        case AnalysisEvent.COMPLETED:
            print(f"Analysis completed: {data.summary.overall_score}/100")

analyzer.on(AnalysisEvent.ISSUE_FOUND, progress_handler)
```

### 3. Multiple Report Formats
```python
result = await analyzer.analyze()
report = Report(result)

# Export in different formats
print(report.to_markdown())
report.save_json("report.json")
report.save_html("report.html")
report.save_yaml("report.yaml")

# Streaming markdown report
async for chunk in report.stream_markdown():
    print(chunk, end="")
```

### 4. Plugin System
```python
# Custom detector plugin
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

# Usage
analyzer.with_plugin(CustomAPIDetector())
```

---

## 🔄 Code Migration References

### From Old Project → New Location

| Old File | New Location | Key Changes |
|----------|-------------|-------------|
| `netstealth-analyzer-old/models.py` | Split into `models/*.py` | Async support, better separation, Pydantic v2 |
| `netstealth-analyzer-old/core.py` | `analyzer.py` + `core/pipeline.py` | Fluent API, event-driven, async |
| `netstealth-analyzer-old/parsers/*.py` | `parsers/*.py` | Add async, streaming, error handling |
| `netstealth-analyzer-old/detectors/*.py` | `detectors/*.py` | Plugin interface, async, registry |
| `netstealth-analyzer-old/reports/summary.py` | `reporting/reporter.py` | Incremental generation, multiple formats |

### Key Code Patterns to Port

1. **Issue Detection Logic**: Extract from old detectors, make async
2. **Log Parsing**: Port parsing logic, add streaming support
3. **Network Trace Building**: Enhance with async processing
4. **Configuration Models**: Upgrade to Pydantic v2
5. **Report Generation**: Add incremental and streaming capabilities

---

## 📊 File Size Estimates

| Component | Files | Approx Lines | Purpose |
|-----------|-------|--------------|---------|
| **Core** | 5 | ~750 | Main analyzer, pipeline, events |
| **Models** | 4 | ~400 | Data structures |
| **Parsers** | 6 | ~770 | Log parsing |
| **Detectors** | 7 | ~910 | Issue detection |
| **Reporting** | 4 | ~600 | Report generation |
| **Utils** | 4 | ~320 | Helpers |
| **Plugins** | 2 | ~130 | Plugin system |
| **Total** | **32 files** | **~3,880 lines** | |

---

## 🚀 Quick Start Commands

```bash
# Initial setup (from tidal_stealth_bundle directory)
cd netstealth-analyzer

# Install dependencies
poetry install

# Run tests
poetry run pytest

# Format code
poetry run black src/ tests/
poetry run ruff check src/ tests/

# Type checking
poetry run mypy src/

# Start development
poetry shell
```

---

## 📊 Success Metrics

- [ ] All tests passing with >80% coverage
- [ ] Async analysis 3x faster than v1
- [ ] Plugin system with 2+ example plugins
- [ ] All 4 report formats working (JSON, Markdown, HTML, YAML)
- [ ] Event-driven progress tracking functional
- [ ] Fluent API intuitive and documented
- [ ] Zero breaking changes for basic usage patterns
- [ ] Python 3.13+ compatibility confirmed
- [ ] Memory usage optimized for large log files
- [ ] Error handling covers all failure scenarios

---

## 🔗 Reference Links

- **Old Project**: `../netstealth-analyzer-old/`
- **Python 3.13 Docs**: https://docs.python.org/3.13/
- **Python 3.13 Features**: https://docs.python.org/3.13/whatsnew/3.13.html
- **Asyncio Guide**: https://docs.python.org/3/library/asyncio.html
- **Pydantic v2**: https://docs.pydantic.dev/latest/
- **Poetry Documentation**: https://python-poetry.org/docs/

---

## 📝 Development Notes

### Context Preservation
This document serves as the complete blueprint for the NetStealth Analyzer v2.0 refactor. Each section can be implemented independently, and the checklist ensures nothing is missed even if development context is lost.

### Code Quality Standards
- **Type Hints**: All functions must have complete type annotations
- **Docstrings**: Google-style docstrings for all public APIs
- **Error Handling**: Structured exceptions with context
- **Testing**: Unit tests for all components, integration tests for workflows
- **Documentation**: API docs, examples, and migration guides

### Performance Targets
- **Startup Time**: < 500ms for basic analysis setup
- **Memory Usage**: < 100MB for typical log files (< 50MB)
- **Processing Speed**: > 1000 log entries per second
- **Concurrent Operations**: Support 10+ concurrent analyses

---

**Status**: 📋 Planning Complete - Ready for Implementation  
**Next Step**: Begin Phase 1 implementation starting with compatibility layer

---

*This technical specification is a living document and will be updated as implementation progresses.*
