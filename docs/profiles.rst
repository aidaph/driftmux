Scan profiles
=============

driftmux uses profiles to control how active the assessment should be.

Passive
-------

The ``passive`` profile is the safest mode.

It focuses on discovery and passive enrichment. Active template execution should
be skipped in this mode.

Example:

.. code-block:: bash

   driftmux --host example.org --profile passive

Use this mode when you want a conservative first look at a host.

Fast
----

The ``fast`` profile is designed for regular use.

It can run selected high-signal checks, avoiding noisy or intrusive categories
such as fuzzing, denial-of-service, brute force and headless checks.

Example:

.. code-block:: bash

   driftmux --host example.org --profile fast

Deep
----

The ``deep`` profile enables broader checks.

Use it when you have explicit authorization and want a more complete assessment:

.. code-block:: bash

   driftmux --host example.org --profile deep

Choosing a profile
------------------

.. list-table::
   :header-rows: 1

   * - Profile
     - Best for
     - Active checks
   * - ``passive``
     - initial review, low-noise recon
     - no
   * - ``fast``
     - day-to-day security checks
     - limited
   * - ``deep``
     - authorized deeper assessments
     - broader
