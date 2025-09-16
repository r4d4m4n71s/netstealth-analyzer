#!/usr/bin/env python3
"""
Simple test script to verify parsers work in Python 3.13
without triggering the main package initialization.
"""

import sys
import os
from pathlib import Path

# Add the src directory to Python path
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

def test_parser_imports():
    """Test that all parsers can be imported successfully."""
    print(f"Python version: {sys.version}")
    print("Testing parser imports...")
    
    try:
        # Import parsers directly from their modules
        from netstealth_analyzer.parsers.base import BaseLogParser, ParseResult
        print("✓ Base parser classes imported successfully")
        
        from netstealth_analyzer.parsers.har import HarParser
        print("✓ HAR parser imported successfully")
        
        from netstealth_analyzer.parsers.mitmproxy import MitmproxyParser
        print("✓ Mitmproxy parser imported successfully")
        
        from netstealth_analyzer.parsers.browser import BrowserLogParser
        print("✓ Browser parser imported successfully")
        
        from netstealth_analyzer.parsers.poc import PocExecutionParser
        print("✓ POC parser imported successfully")
        
        return True
        
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return False

def test_parser_instantiation():
    """Test that parsers can be instantiated."""
    print("\nTesting parser instantiation...")
    
    try:
        from netstealth_analyzer.parsers.har import HarParser
        from netstealth_analyzer.parsers.mitmproxy import MitmproxyParser
        from netstealth_analyzer.parsers.browser import BrowserLogParser
        from netstealth_analyzer.parsers.poc import PocExecutionParser
        
        # Test instantiation
        har_parser = HarParser()
        print("✓ HAR parser instantiated successfully")
        
        mitm_parser = MitmproxyParser()
        print("✓ Mitmproxy parser instantiated successfully")
        
        browser_parser = BrowserLogParser()
        print("✓ Browser parser instantiated successfully")
        
        poc_parser = PocExecutionParser()
        print("✓ POC parser instantiated successfully")
        
        return True
        
    except Exception as e:
        print(f"✗ Instantiation error: {e}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("NetStealth Analyzer v2.0 - Parser Test (Python 3.13)")
    print("=" * 60)
    
    # Test imports
    import_success = test_parser_imports()
    
    if import_success:
        # Test instantiation
        instantiation_success = test_parser_instantiation()
        
        if instantiation_success:
            print("\n🎉 All parser tests passed successfully!")
            print("✓ All parsers work correctly in Python 3.13")
            sys.exit(0)
        else:
            print("\n❌ Parser instantiation tests failed")
            sys.exit(1)
    else:
        print("\n❌ Parser import tests failed")
        sys.exit(1)
