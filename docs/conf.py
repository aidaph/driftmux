# docs/conf.py

from __future__ import annotations

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
html_title = "driftmux"
html_short_title = "driftmux"

html_theme_options = {
    "navigation_depth": 4,
    "collapse_navigation": False,
    "sticky_navigation": True,
}

autodoc_typehints = "description"
autosummary_generate = True
add_module_names = False
