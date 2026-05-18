OpenStack Neutron Security Group Audit
======================================

Driftmux can audit OpenStack Neutron security groups to detect public exposure
of critical ports.

This mode does not scan virtual machines directly. Instead, it queries the
OpenStack API and analyses Neutron security group rules.

It is useful when the cloud administrator does not have access to the guest
operating systems but still wants to identify dangerous network exposure at the
cloud layer.

What it detects
---------------

The OpenStack scanner detects ingress security group rules that expose critical
ports to public CIDRs such as:

.. code-block:: text

   0.0.0.0/0
   ::/0

Examples of detected exposures:

.. code-block:: text

   SSH 22/tcp exposed to 0.0.0.0/0
   RDP 3389/tcp exposed to 0.0.0.0/0
   PostgreSQL 5432/tcp exposed to 0.0.0.0/0
   Redis 6379/tcp exposed to 0.0.0.0/0
   Elasticsearch/OpenSearch 9200/tcp exposed to 0.0.0.0/0
   Docker API 2375/tcp exposed to 0.0.0.0/0
   Kubernetes API 6443/tcp exposed to 0.0.0.0/0
   All ports exposed to 0.0.0.0/0

By default, HTTP and HTTPS exposure on ports ``80/tcp`` and ``443/tcp`` is not
reported as a high-risk finding.

What it does not do
-------------------

The OpenStack scanner does not log into virtual machines.

It does not inspect:

.. code-block:: text

   Guest operating systems
   Installed packages inside VMs
   Local users
   Processes
   Rootkits
   Filesystem integrity
   Application logs inside the VM

It only analyses the cloud networking configuration available through the
OpenStack API.

Requirements
------------

The scanner requires:

.. code-block:: text

   openstacksdk
   Valid OpenStack credentials
   Permissions to list Neutron security group rules
   Permissions to list Neutron ports
   Permissions to read projects and servers, if usage enrichment is enabled

Install the Python dependency:

.. code-block:: bash

   pip install openstacksdk

If you installed Driftmux in editable mode:

.. code-block:: bash

   pip install -e .

Authentication
--------------

The scanner supports the usual OpenStack authentication methods.

Using clouds.yaml
~~~~~~~~~~~~~~~~~

Example:

.. code-block:: bash

   driftmux --openstack-sg-audit --os-cloud openstack

Using an OpenRC file
~~~~~~~~~~~~~~~~~~~~

Example:

.. code-block:: bash

   source admin-openrc.sh
   driftmux --openstack-sg-audit --format markdown

Basic usage
-----------

Run the OpenStack security group audit:

.. code-block:: bash

   driftmux --openstack-sg-audit --os-cloud openstack --format markdown

Generate JSON output:

.. code-block:: bash

   driftmux --openstack-sg-audit --os-cloud openstack --format json

Generate CSV output:

.. code-block:: bash

   driftmux --openstack-sg-audit --os-cloud openstack --format csv

Output files
------------

The OpenStack audit generates a dedicated report name:

.. code-block:: text

   reports/driftmux-openstack-neutron-security-groups.md
   reports/driftmux-openstack-neutron-security-groups.json
   reports/driftmux-openstack-neutron-security-groups.csv

This avoids mixing OpenStack findings with host-based scan reports.

Console output
--------------

The console output summarizes findings grouped by project.

Example:

.. code-block:: text

   OpenStack Neutron Security Group Audit
   Checked rules: 3254
   Findings: 340
   Errors: 0

   [project-a] total=12 critical=1 high=11
     - CRITICAL sg=default ports=all src=0.0.0.0/0 match=all_ports used_by=3
     - HIGH sg=k8s-master ports=22 src=0.0.0.0/0 match=22/SSH used_by=2

   [project-b] total=2 critical=0 high=2
     - HIGH sg=elasticsearch ports=9200 src=0.0.0.0/0 match=9200/Elasticsearch/OpenSearch used_by=1

Markdown report
---------------

The Markdown report groups findings by project:

.. code-block:: markdown

   # Driftmux report

   ## Driftmux OpenStack Neutron Security Group Audit

   - Checked rules: 3254
   - Findings: 340
   - Errors: 0

   ### Project: datalab-users `project-id`

   - Total findings: 12
   - Critical: 1
   - High: 11
   - Medium: 0
   - Low: 0
   - Info: 0

   | Severity | Security group | Protocol | Ports | Source | Match | Used by ports | Used by servers | Rule ID |
   |---|---|---|---|---|---|---:|---:|---|
   | CRITICAL | default | any | all | 0.0.0.0/0 | all_ports | 3 | 2 | rule-id |
   | HIGH | ssh-public | tcp | 22 | 0.0.0.0/0 | 22/SSH | 1 | 1 | rule-id |

JSON output
-----------

Each finding is represented using the common Driftmux finding model.

Example:

.. code-block:: json

   {
     "scanner": "openstack",
     "host": "openstack:neutron",
     "title": "OpenStack security group exposure: datalab/default exposes all ports to 0.0.0.0/0 (all_ports) [active, servers=2]",
     "severity": "critical",
     "description": "OpenStack Neutron security group rule exposes a critical port or port range to a public CIDR.",
     "evidence": "rule_id=... sg=default project=datalab direction=ingress protocol=None ports=None-None remote_ip_prefix=0.0.0.0/0 used_by_ports=3 used_by_servers=2 exposure_status=active",
     "confidence": "high",
     "port": null,
     "service": "neutron-security-group",
     "metadata": {
       "event_type": "openstack_security_group_exposure",
       "project_id": "project-id",
       "project_name": "datalab",
       "security_group_id": "security-group-id",
       "security_group_name": "default",
       "remote_ip_prefix": "0.0.0.0/0",
       "matched": [
         "all_ports"
       ],
       "used_by_count": 3,
       "used_by_server_count": 2,
       "exposure_status": "active"
     }
   }

Active and unused exposures
---------------------------

The OpenStack scanner distinguishes between two states:

.. code-block:: text

   active
   unused

Active exposure
~~~~~~~~~~~~~~~

A finding is marked as ``active`` when the security group is attached to at
least one Neutron port.

Example:

.. code-block:: text

   SSH 22/tcp exposed to 0.0.0.0/0 and applied to one or more VM ports

Unused exposure
~~~~~~~~~~~~~~~

A finding is marked as ``unused`` when the rule exists but the security group
is not currently attached to any Neutron port.

Example:

.. code-block:: text

   SSH 22/tcp exposed to 0.0.0.0/0 but the security group is not used by any port

Unused exposures are still reported because they may become dangerous if the
security group is later attached to a server.

Severity model
--------------

The default severity model is:

+--------------------------------------------------+-----------+-----------+
| Condition                                        | Active SG | Unused SG |
+==================================================+===========+===========+
| All ports exposed to ``0.0.0.0/0`` or ``::/0``   | Critical  | High      |
+--------------------------------------------------+-----------+-----------+
| Critical service exposed to ``0.0.0.0/0`` or     | High      | Medium    |
| ``::/0``                                         |           |           |
+--------------------------------------------------+-----------+-----------+
| HTTP/HTTPS only                                  | Info or   | Info or   |
|                                                  | ignored   | ignored   |
+--------------------------------------------------+-----------+-----------+

Examples:

.. code-block:: text

   0.0.0.0/0 -> all ports -> active -> CRITICAL
   0.0.0.0/0 -> 22/tcp -> active -> HIGH
   0.0.0.0/0 -> 22/tcp -> unused -> MEDIUM
   0.0.0.0/0 -> 80/tcp -> ignored by default
   0.0.0.0/0 -> 443/tcp -> ignored by default

Critical ports
--------------

By default, Driftmux checks for common administrative, database and
infrastructure ports.

+-------------+--------------------------------+
| Port        | Service                        |
+=============+================================+
| 22          | SSH                            |
+-------------+--------------------------------+
| 3389        | RDP                            |
+-------------+--------------------------------+
| 3306        | MySQL/MariaDB                  |
+-------------+--------------------------------+
| 5432        | PostgreSQL                     |
+-------------+--------------------------------+
| 6379        | Redis                          |
+-------------+--------------------------------+
| 27017       | MongoDB                        |
+-------------+--------------------------------+
| 9200        | Elasticsearch/OpenSearch       |
+-------------+--------------------------------+
| 5601        | Kibana/OpenSearch Dashboards   |
+-------------+--------------------------------+
| 8080        | HTTP alternative/Tomcat        |
+-------------+--------------------------------+
| 8443        | HTTPS alternative              |
+-------------+--------------------------------+
| 9092        | Kafka                          |
+-------------+--------------------------------+
| 11211       | Memcached                      |
+-------------+--------------------------------+
| 2049        | NFS                            |
+-------------+--------------------------------+
| 445         | SMB                            |
+-------------+--------------------------------+
| 389         | LDAP                           |
+-------------+--------------------------------+
| 636         | LDAPS                          |
+-------------+--------------------------------+
| 2375        | Docker API without TLS         |
+-------------+--------------------------------+
| 2376        | Docker API with TLS            |
+-------------+--------------------------------+
| 6443        | Kubernetes API                 |
+-------------+--------------------------------+
| 10250       | Kubelet                        |
+-------------+--------------------------------+
| 5900-5999   | VNC                            |
+-------------+--------------------------------+

Security group usage enrichment
-------------------------------

Driftmux tries to determine whether each affected security group is currently
used.

It builds the following relationship:

.. code-block:: text

   security_group_rule
           |
           v
   security_group
           |
           v
   neutron port.security_group_ids
           |
           v
   port.device_id
           |
           v
   nova server

The scanner enriches findings with:

.. code-block:: text

   used_by_count
   used_by_server_count
   used_by_ports
   used_by_servers
   exposure_status

Example metadata:

.. code-block:: json

   {
     "used_by_count": 2,
     "used_by_server_count": 1,
     "used_by_servers": [
       {
         "server_id": "server-id",
         "server_name": "vm-01",
         "status": "ACTIVE",
         "project_id": "project-id"
       }
     ],
     "exposure_status": "active"
   }

Important limitation
--------------------

``exposure_status=active`` means that the security group is attached to at
least one Neutron port.

It does not prove that traffic has actually reached the VM.

To know whether the exposed rule is receiving traffic, you need network
telemetry such as:

.. code-block:: text

   Neutron security group logging
   OVN/OVS flow logs
   Suricata
   Zeek
   Firewall logs
   Router logs
