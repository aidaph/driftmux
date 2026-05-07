Architecture
============

driftmux is built as a small pipeline.

The main stages are:

#. service discovery;
#. parsing and normalization;
#. passive enrichment;
#. scan planning;
#. active checks;
#. reporting.

Pipeline overview
-----------------

.. code-block:: text

   Host
    |
    v
   NmapScanner
    |
    v
   NmapXmlParser
    |
    v
   HostScanResult
    |
    +--> NVD enrichment
    |
    +--> ScanPlan
           |
           +--> Nuclei targets
           +--> WordPress targets
    |
    v
   Final report

Models
------

The central model is ``HostScanResult``. It contains:

* discovered services;
* findings;
* tool errors;
* metadata.

Open ports are represented as normalized service objects. They can include:

* port;
* protocol;
* state;
* service name;
* product;
* version;
* extra information;
* tunnel;
* CPEs;
* classifications.

Planner
-------

The planner decides which tools should run against which services.

It receives:

* the host;
* discovered services;
* passive findings;
* selected scheme;
* scan profile.

It returns a ``ScanPlan`` containing:

* Nuclei targets;
* WordPress targets;
* passive-only status.

Nuclei integration
------------------

Nuclei execution is target-based.

Instead of launching the whole template catalog against every service, driftmux
groups targets by tags and runs focused template categories.

This keeps scans easier to reason about and reduces unnecessary noise.

NVD enrichment
--------------

NVD enrichment works best when Nmap provides product, version or CPE evidence.

When Nmap only returns ``tcpwrapped`` or ``unknown`` services, driftmux may still
report the exposed service, but there may be no reliable vulnerability match.

This is expected:

.. code-block:: text

   80/tcp open tcpwrapped

is not enough to infer a specific vulnerable product such as Apache, Nginx,
Tomcat or OpenSSH.
