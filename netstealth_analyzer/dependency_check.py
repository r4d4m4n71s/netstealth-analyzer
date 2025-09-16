"""
Simple NetStealth dependency check that raises clear errors.
"""

def check_netstealth_dependencies():
    """Check if NetStealth can run. Raises error if not."""
    
    missing = []
    
    # Check critical imports
    try:
        import netstealth
    except ImportError:
        missing.append("netstealth (run: pip install -e /path/to/netstealth)")
    
    try:
        import selenium
    except ImportError:
        missing.append("selenium (run: pip install selenium)")
    
    try:
        import undetected_chromedriver
    except ImportError:
        missing.append("undetected-chromedriver (run: pip install undetected-chromedriver)")
    
    try:
        import setuptools  # Required for undetected_chromedriver
    except ImportError:
        missing.append("setuptools (run: pip install setuptools)")
    
    # Raise single clear error if anything missing
    if missing:
        error_msg = f"""
❌ NetStealth Dependencies Missing:

{chr(10).join(f'  • {dep}' for dep in missing)}

Fix with:
  pip install selenium undetected-chromedriver setuptools
"""
        raise ImportError(error_msg)
    
    return True
