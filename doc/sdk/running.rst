Running Service
===============

Once the VirusTotal API DXL service has been installed and the configuration files are populated it can be started by
executing the following command line:

    .. parsed-literal::

        python -m dxlvtapiservice <configuration-directory>

    The ``<configuration-directory>`` argument must point to a directory containing the configuration files
    required for the VirusTotal API DXL service (see :doc:`configuration`).

For example:

    .. parsed-literal::

        python -m dxlvtapiservice config

Output
------

The output from starting the service should appear similar to the following:

    .. parsed-literal::

        Running application ...
        On 'run' callback.
        On 'load configuration' callback.
        Incoming message configuration: queueSize=1000, threadCount=10
        Message callback configuration: queueSize=1000, threadCount=10
        Attempting to connect to DXL fabric ...
        Connected to DXL fabric.
        Registering service: vtapiservice
        Registering request callback: file_rescan
        Registering request callback: file_report
        Registering request callback: url_scan
        Registering request callback: url_report
        Registering request callback: ipaddress_report
        Registering request callback: domain_report
        On 'DXL connect' callback.
