Docker Support
==============

A pre-built Docker image can be used as an alternative to installing a Python environment with the
libraries required for the VirusTotal API DXL service. Docker images for the VirusTotal API DXL service are posted to the
following Docker repository:

`<https://hub.docker.com/r/opendxl/opendxl-vtapi-service-python/>`_

The remainder of this page walks through the steps required to configure the service,
pull the image from the repository, and run the VirusTotal API DXL service via a Docker container.

Service Configuration
---------------------

The first step is to connect to the host that is running Docker and configure the VirusTotal API DXL service. The configuration
files that are required for the VirusTotal API DXL service will reside on the host system and be made available to the Docker
container via a data volume.

Once you have logged into the host system, perform the following steps:

    1.) Create a directory to contain the configuration files

        .. container:: note, admonition

            mkdir dxlvtapiservice-config

    2.) Change to the newly created directory

        .. container:: note, admonition

            cd dxlvtapiservice-config

    3.) Download the latest configuration files for the VirusTotal API DXL service

        The latest release of the service can be found at the following page:

        `<https://github.com/opendxl/opendxl-vtapi-service-python/releases/latest>`_

        Download the latest configuration package (dxlvtapiservice-python-dist-config). For example:

        .. container:: note, admonition

           wget ht\ tps://github.com/opendxl/opendxl-vtapi-service-python/releases/download/\ |version|\/dxlvtapiservice-python-dist-config-\ |version|\.zip

    4.) Extract the configuration package

        .. container:: note, admonition

           unzip dxlvtapiservice-python-dist-config-\ |version|\.zip

    5.) Populate the configuration files:

        * :ref:`Client Configuration File <dxl_client_config_file_label>`
        * :ref:`Service Configuration File <dxl_service_config_file_label>`

Pull Docker Image
-----------------

The next step is to `pull` the VirusTotal API DXL service image from the Docker repository.

The image can be pulled using the following Docker command:

    :literal:`docker pull opendxl/opendxl-vtapi-service-python:<release-version>`

    The following parameters must be specified:

        * ``release-version``
          The release version of the VirusTotal API DXL service

For example:

    .. container:: note, admonition

        docker pull opendxl/opendxl-vtapi-service-python:\ |version|\

Create Docker Container
-----------------------

The final step is to create a Docker container based on the pulled image.

The container can be created using the following Docker command:

    :literal:`docker run -d --name dxlvtapiservice -v <host-config-dir>:/opt/dxlvtapiservice-config opendxl/opendxl-vtapi-service-python:<release-version>`

    The following parameters must be specified:

        * ``host-config-dir``
          The directory on the host that contains the service configuration files
        * ``release-version``
          The version of the image (See "Pull Docker Image" section above)

For example:

    .. container:: note, admonition

        docker run -d --name dxlvtapiservice -v /home/myuser/dxlvtapiservice-config:/opt/dxlvtapiservice-config opendxl/opendxl-vtapi-service-python:\ |version|\

**Note:** A restart policy can be specified via the restart flag (``--restart <policy>``). This flag can be used to restart
the container when the system reboots or if the service terminates abnormally. The ``unless-stopped`` policy will
restart the container unless it has been explicitly stopped.

Additional Docker Commands
--------------------------

The following Docker commands are useful once the container has been created.

    * **Container Status**

        The ``ps`` command can be used to show the status of the container.

            :literal:`docker ps --filter name=dxlvtapiservice`

        Example output:

            .. parsed-literal::

                CONTAINER ID  COMMAND                 CREATED        STATUS
                c60eaf0788fe  "python -m dxlvtapiserv"  7 minutes ago  Up 7 minutes

    * **Container Logs**

        The ``logs`` command can be used to display the log messages for the container.

            :literal:`docker logs dxlvtapiservice`

        Example output:

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

        The log output can be `followed` by adding a ``-f`` flag (similar to tail) to the logs command.

    * **Stop/Restart/Start**

        The container can be stopped, restarted, and started using the following commands:

            * ``docker stop dxlvtapiservice``
            * ``docker restart dxlvtapiservice``
            * ``docker start dxlvtapiservice``