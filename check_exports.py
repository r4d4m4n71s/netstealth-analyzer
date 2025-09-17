#!/usr/bin/env python3
"""
Check what's actually exported from modules to fix test imports.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

print('Checking network.py exports:')
try:
    from netstealth_analyzer.models import network
    exports = [name for name in dir(network) if not name.startswith('_')]
    print('Available in network module:', exports)
except Exception as e:
    print('Error:', e)

print('\nChecking builder.py exports:')
try:
    from netstealth_analyzer import builder
    exports = [name for name in dir(builder) if not name.startswith('_')]
    print('Available in builder module:', exports)
except Exception as e:
    print('Error:', e)

print('\nChecking what NetworkTrace actually needs:')
try:
    from netstealth_analyzer.models.network import NetworkTrace
    print('✅ NetworkTrace imported successfully')
    
    # Check what's in the __all__ export
    import netstealth_analyzer.models.network as net_mod
    if hasattr(net_mod, '__all__'):
        print('__all__ exports:', net_mod.__all__)
    else:
        print('No __all__ defined')
        
except Exception as e:
    print('Error importing NetworkTrace:', e)
