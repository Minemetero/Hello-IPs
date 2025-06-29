import os
import sys


def resource_path(*segments):
    """Return the absolute path to a resource bundled with the application."""
    if getattr(sys, 'frozen', False):
        base_path = os.path.dirname(sys.executable)
    else:
        base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    return os.path.join(base_path, *segments)
