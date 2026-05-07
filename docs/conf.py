# docs/conf.py

from __future__ import annotations

import os
import sys
from pathlib import Path

# Permite que Sphinx importe tu paquete desde la raíz del repo
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

project = "driftmux"
author = "aidaph"
copyright = "2026, aidaph"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "myst_parser",
]

autosummary_generate = True
autodoc_typehints = "description"

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]
