"""
Pytest configuration for ORACLE test suites.
Ensures the backend package is in the Python search path.
"""

import sys
import os

# Add root project path to sys.path so 'backend' can be imported anywhere in tests
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)
