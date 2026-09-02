"""Threat Modeling as Code for Python.

A declarative STRIDE threat-modeling library. Express systems as components,
trust boundaries, and data flows, then analyze them to get targeted mitigations.
"""

from .model import (
    Boundary,
    Component,
    DataFlow,
    Model,
    Threat,
    ThreatKind,
)

__version__ = "1.0.0"

__all__ = [
    "Boundary",
    "Component",
    "DataFlow",
    "Model",
    "Threat",
    "ThreatKind",
    "__version__",
]
