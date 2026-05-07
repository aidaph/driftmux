driftmux documentation
======================

**driftmux** is a security reconnaissance and vulnerability correlation tool
designed to turn noisy scan output into a clearer, structured view of exposed
services, potential weaknesses, and actionable findings.

It combines service discovery, vulnerability enrichment and targeted template
execution into a single workflow.

.. note::

   driftmux is intended for authorized security testing, internal asset review,
   research environments and defensive assessments. Do not scan systems you do
   not own or do not have permission to test.

What driftmux does
------------------

driftmux helps you:

* discover exposed TCP services with Nmap;
* parse open ports, service names, versions and CPEs;
* enrich detected software with vulnerability intelligence;
* plan targeted checks for web-facing services;
* run Nuclei templates against selected URLs;
* inspect WordPress targets with Plecost when applicable;
* generate structured reports for later analysis.

Core idea
---------

Instead of running every scanner against every target, driftmux builds a
lightweight scan plan from the information already discovered.

For example:

#. Nmap identifies open ports and available service fingerprints.
#. driftmux classifies services such as HTTP, HTTPS, WordPress, Apache, Nginx or Tomcat.
#. The planner creates focused Nuclei targets only for relevant web services.
#. Vulnerability backends such as NVD are queried when there is enough product,
   version or CPE evidence.
#. Results are merged into a single host report.

Contents
--------

.. toctree::
   :maxdepth: 2
   :caption: User guide

   installation
   quickstart
   profiles
   cli

.. toctree::
   :maxdepth: 2
   :caption: Internals

   architecture
   api
