"""
SecureShare Cybersecurity - Log Analyzer Module
Author: Anfas
Role: Cybersecurity Log Analyzer & Threat Detection
"""

import os
import sys

# Ensure local module directory is in sys.path for robust resolution
_analyzer_dir = os.path.dirname(os.path.abspath(__file__))
if _analyzer_dir not in sys.path:
    sys.path.insert(0, _analyzer_dir)

try:
    from .parser import LogEntry, LogParser  # type: ignore[missing-import] # pyrefly: ignore
    from .detector import LogAnalyzer, SecurityAlert  # type: ignore[missing-import] # pyrefly: ignore
    from .server import run_server, LogAnalyzerServer  # type: ignore[missing-import] # pyrefly: ignore
except (ImportError, ValueError):
    from parser import LogEntry, LogParser  # type: ignore[missing-import] # pyrefly: ignore
    from detector import LogAnalyzer, SecurityAlert  # type: ignore[missing-import] # pyrefly: ignore
    from server import run_server, LogAnalyzerServer  # type: ignore[missing-import] # pyrefly: ignore

__version__ = "1.0.0"
__author__ = "Anfas"
__all__ = [
    "LogEntry",
    "LogParser",
    "SecurityAlert",
    "LogAnalyzer",
    "run_server",
    "LogAnalyzerServer",
]
