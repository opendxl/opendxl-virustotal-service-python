Configuration
=============

The VirusTotal API DXL service requires a set of configuration files to operate.

This distribution contains a ``config`` sub-directory that includes the configuration files that must
be populated prior to running the service.

Each of these files are documented throughout the remained of this page.

Application configuration directory:

    .. code-block:: python

        config/
            dxlclient.config
            dxlvtapiservice.config
            logging.config (optional)

.. _dxl_client_config_file_label:

DXL Client Configuration File (dxlclient.config)
------------------------------------------------

    The required ``dxlclient.config`` file is used to configure the DXL client that will connect to the DXL fabric.

    The steps to populate this configuration file are the same as those documented in the `OpenDXL Python
    SDK`, see the
    `OpenDXL Python SDK Samples Configuration <https://opendxl.github.io/opendxl-client-python/pydoc/sampleconfig.html>`_
    page for more information.

    The following is an example of a populated DXL client configuration file:

        .. code-block:: python

            [Certs]
            BrokerCertChain=c:\\certificates\\brokercerts.crt
            CertFile=c:\\certificates\\client.crt
            PrivateKey=c:\\certificates\\client.key

            [Brokers]
            {5d73b77f-8c4b-4ae0-b437-febd12facfd4}={5d73b77f-8c4b-4ae0-b437-febd12facfd4};8883;mybroker.mcafee.com;192.168.1.12
            {24397e4d-645f-4f2f-974f-f98c55bdddf7}={24397e4d-645f-4f2f-974f-f98c55bdddf7};8883;mybroker2.mcafee.com;192.168.1.13

.. _dxl_service_config_file_label:

VirusTotal API DXL service (dxlvtapiservice.config)
---------------------------------------------------

    The required ``dxlvtapiservice.config`` file is used to configure the service.

    The following is an example of a populated application configuration file:

        .. code-block:: python

            [General]
            # The Virus Total API Key (required)
            apiKey=-- YOUR API KEY --

    **General**

        The ``General`` section is used to specify the VirusTotal API key.

        +------------------------+----------+--------------------------------------------------------------------+
        | Name                   | Required | Description                                                        |
        +========================+==========+====================================================================+
        | apiKey                 | yes      | The VirusTotal API key used for authenticating with VirusTotal.    |
        +------------------------+----------+--------------------------------------------------------------------+

Logging File (logging.config)
-----------------------------

    The optional ``logging.config`` file is used to configure how the application writes log messages.
