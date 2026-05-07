Quickstart
==========

Basic scan
----------

Run a basic scan against a host:

.. code-block:: bash

   driftmux --host example.org

Scan a specific IP:

.. code-block:: bash

   driftmux --host 193.146.75.190

Specify ports manually
----------------------

If service discovery is unstable or the target is behind filtering, pass known
ports explicitly:

.. code-block:: bash

   driftmux --host 193.146.75.190 --ports 80,443,8443

This avoids relying on a discovery pass and tells Nmap exactly which ports should
be inspected.

Use a profile
-------------

Passive profile:

.. code-block:: bash

   driftmux --host example.org --profile passive

Fast profile:

.. code-block:: bash

   driftmux --host example.org --profile fast

Deep profile:

.. code-block:: bash

   driftmux --host example.org --profile deep

Use NVD enrichment
------------------

Run a scan and only keep vulnerabilities above a given CVSS threshold:

.. code-block:: bash

   driftmux --host example.org \
     --vuln-backend nvd \
     --min-cvss 7.0

Run Nmap scripts
----------------

You can pass Nmap scripts to improve fingerprinting for web services:

.. code-block:: bash

   driftmux --host example.org \
     --ports 80,443,8443 \
     --nmap-script http-title,http-server-header,http-headers,ssl-cert

Output
------

A typical console result looks like this:

.. code-block:: text

[205.87.65.183]
Services: 1 | Findings: 4 | Errors: 1
  - 22/tcp     ssh          OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 [ssh]
  * CRITICAL nvd: CVE-2008-3844 affects OpenSSH
  * HIGH nvd: CVE-2024-6387 affects OpenSSH
  * HIGH nvd: CVE-2026-35385 affects OpenSSH
  * HIGH nvd: CVE-2023-51767 affects OpenSSH

The JSON report is saved under:

.. code-block:: text

   reports/driftmux-report.json
