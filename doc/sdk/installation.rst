Installation
============

Prerequisites
*************

* OpenDXL Python Client library installed
   `<https://github.com/opendxl/opendxl-client-python>`_

* The OpenDXL Python Client prerequisites must be satisfied
   `<https://opendxl.github.io/opendxl-client-python/pydoc/installation.html>`_

* Python 2.7.9 or higher in the Python 2.x series or Python 3.4.0 or higher
  in the Python 3.x series installed within a Windows or Linux environment.

* A valid VirusTotal API Key (See `VirusTotal Getting started <https://www.virustotal.com/en/documentation/public-api/#getting-started>`_ for more information)
   The API key must be specified in the :ref:`Service Configuration File <dxl_service_config_file_label>`

Installation
************

This distribution contains a ``lib`` sub-directory that includes the service library files.

Use ``pip`` to automatically install the service library:

    .. parsed-literal::

        pip install dxlvtapiservice-\ |version|\-py2.py3-none-any.whl

Or with:

    .. parsed-literal::

        pip install dxlvtapiservice-\ |version|\.zip

As an alternative (without PIP), unpack the dxlvtapiservice-\ |version|\.zip (located in the lib folder) and run the setup
script:

    .. parsed-literal::

        python setup.py install
