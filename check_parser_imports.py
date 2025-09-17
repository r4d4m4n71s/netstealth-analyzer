#!/usr/bin/env python3
"""
Check what parsers are trying to import from network models.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

def check_parser_imports():
    """Check what each parser is trying to import."""
    parser_files = [
        'src/netstealth_analyzer/parsers/har.py',
        'src/netstealth_analyzer/parsers/base.py',
        'src/netstealth_analyzer/parsers/mitmproxy.py',
        'src/netstealth_analyzer/parsers/browser.py',
        'src/netstealth_analyzer/parsers/poc.py'
    ]
    
    for parser_file in parser_files:
        print(f"\n=== {parser_file} ===")
        try:
            with open(parser_file, 'r') as f:
                content = f.read()
                
            # Find import lines from network models
            lines = content.split('\n')
            for i, line in enumerate(lines, 1):
                if 'from ..models.network import' in line or 'from netstealth_analyzer.models.network import' in line:
                    print(f"Line {i}: {line.strip()}")
                    
        except FileNotFoundError:
            print(f"File not found: {parser_file}")
        except Exception as e:
            print(f"Error reading {parser_file}: {e}")

if __name__ == "__main__":
    check_parser_imports()
