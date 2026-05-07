Installation
============

Requirements
------------

driftmux is a Python project that orchestrates external security tools.
Depending on the features you want to use, you may need:

* Python 3.10 or newer;
* Nmap;
* Nuclei if profile fast or deep is selected, not used in default passive;
* Plecost, if WordPress checks are enabled;
* internet access for vulnerability enrichment backends such as NVD.

Install from source
-------------------

Clone the repository:

.. code-block:: bash

   git clone https://github.com/aidaph/driftmux.git
   cd driftmux

Create a virtual environment:

.. code-block:: bash

   python -m venv .venv
   source .venv/bin/activate

Install the project in editable mode:

.. code-block:: bash

   pip install -e .

Check that the CLI is available:

.. code-block:: bash

   driftmux --help

Install Nmap
------------

On Debian/Ubuntu systems:

.. code-block:: bash

   sudo apt update
   sudo apt install nmap

Check the installation:

.. code-block:: bash

   nmap --version

Install Nuclei
--------------

Install Nuclei following the official ProjectDiscovery installation method for
your platform, then verify:

.. code-block:: bash

   nuclei -version

If Nuclei is not installed or not available in ``PATH``, driftmux will still run
the rest of the pipeline and report the Nuclei error in the final result.

Optional: OS detection
----------------------

Nmap OS detection usually requires elevated privileges:

.. code-block:: bash

   sudo nmap -sS -O -Pn example.org

In driftmux, OS detection should be treated as an optional capability because it
can be noisier than basic service discovery.
