Command line interface
======================

The main entry point is:

.. code-block:: bash

   driftmux --host <target>

Common options
--------------

``--host``
   Target host, IP address or URL.

``--ports``
   Comma-separated list of ports to scan.

   Example:

   .. code-block:: bash

      driftmux --host example.org --ports 80,443,8443

``--profile``
   Scan profile. Common values are ``passive``, ``fast`` and ``deep``.

``--vuln-backend``
   Vulnerability enrichment backend.

   Example:

   .. code-block:: bash

      driftmux --host example.org --vuln-backend nvd

``--min-cvss``
   Minimum CVSS score for vulnerability findings.

   Example:

   .. code-block:: bash

      driftmux --host example.org --vuln-backend nvd --min-cvss 7.0

``--nmap-script``
   Comma-separated Nmap scripts to run during service discovery.

   Example:

   .. code-block:: bash

      driftmux --host example.org \
        --nmap-script http-title,http-server-header,http-headers,ssl-cert

Examples
--------

Conservative scan:

.. code-block:: bash

   driftmux --host example.org --profile passive

Fast scan with NVD:

.. code-block:: bash

   driftmux --host example.org \
     --profile fast \
     --vuln-backend nvd \
     --min-cvss 7.0

Known web ports:

.. code-block:: bash

   driftmux --host example.org \
     --ports 80,443,8443 \
     --profile fast
