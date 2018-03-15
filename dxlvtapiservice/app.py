from __future__ import absolute_import
import logging

from dxlbootstrap.app import Application
from dxlclient.service import ServiceRegistrationInfo
from .requesthandlers import *


# Configure local logger
logger = logging.getLogger(__name__)


class VirusTotalApiService(Application):
    """
    The "VirusTotal DXL" service class.
    """

    #: The name of the "General" section within the application configuration file
    GENERAL_CONFIG_SECTION = "General"
    #: The property used to specify the VirusTotal API Key in the application
    #: configuration file
    GENERAL_API_KEY_CONFIG_PROP = "apiKey"

    #: The DXL service type for the VirusTotal API
    SERVICE_TYPE = "/opendxl-virustotal/service/vtapi"
    #: The length of the DXL service type string
    SERVICE_TYPE_LENGTH = len(SERVICE_TYPE)

    #: The URL format for VirusTotal API invocations
    VTAPI_URL_FORMAT = "https://www.virustotal.com/vtapi/v2{0}"

    #: The "file rescan" DXL request topic
    REQ_TOPIC_FILE_RESCAN = "{0}/file/rescan".format(SERVICE_TYPE)
    #: The "file report" DXL request topic
    REQ_TOPIC_FILE_REPORT = "{0}/file/report".format(SERVICE_TYPE)
    #: The "url scan" DXL request topic
    REQ_TOPIC_URL_SCAN = "{0}/url/scan".format(SERVICE_TYPE)
    #: The "url report" DXL request topic
    REQ_TOPIC_URL_REPORT = "{0}/url/report".format(SERVICE_TYPE)
    #: The "ip address report" DXL request topic
    REQ_TOPIC_IP_ADDRESS_REPORT = "{0}/ip-address/report".format(SERVICE_TYPE)
    #: The "domain report" DXL request topic
    REQ_TOPIC_DOMAIN_REPORT = "{0}/domain/report".format(SERVICE_TYPE)

    def __init__(self, config_dir):
        """
        Constructor parameters:

        :param config_dir: The location of the configuration files for the
            application
        """
        super(VirusTotalApiService, self).__init__(config_dir, "dxlvtapiservice.config")
        self._api_key = None

    @property
    def api_key(self):
        """
        The VirusTotal API key
        """
        return self._api_key

    @property
    def client(self):
        """
        The DXL client used by the application to communicate with the DXL
        fabric
        """
        return self._dxl_client

    @property
    def config(self):
        """
        The application configuration (as read from the "dxlvtapiservice.config" file)
        """
        return self._config

    def on_run(self):
        """
        Invoked when the application has started running.
        """
        logger.info("On 'run' callback.")

    def on_load_configuration(self, config):
        """
        Invoked after the application-specific configuration has been loaded

        This callback provides the opportunity for the application to parse
        additional configuration properties.

        :param config: The application configuration
        """
        logger.info("On 'load configuration' callback.")

        # API Key
        try:
            self._api_key = config.get(self.GENERAL_CONFIG_SECTION, self.GENERAL_API_KEY_CONFIG_PROP)
        except Exception:
            pass
        if not self._api_key:
            raise Exception("VirusTotal API Key not found in configuration file: {0}"
                            .format(self._app_config_path))

    def on_dxl_connect(self):
        """
        Invoked after the client associated with the application has connected
        to the DXL fabric.
        """
        logger.info("On 'DXL connect' callback.")

    def on_register_services(self):
        """
        Invoked when services should be registered with the application
        """
        # Register service 'vtapiservice'
        logger.info("Registering service: {0}".format("vtapiservice"))
        service = ServiceRegistrationInfo(self._dxl_client, self.SERVICE_TYPE)

        logger.info("Registering request callback: {0}".format("file_rescan"))
        self.add_request_callback(
            service, self.REQ_TOPIC_FILE_RESCAN,
            VirusTotalApiRequestCallback(
                self, False, [VirusTotalApiRequestCallback.PARAM_RESOURCE]), False)

        logger.info("Registering request callback: {0}".format("file_report"))
        self.add_request_callback(
            service, self.REQ_TOPIC_FILE_REPORT,
            VirusTotalApiRequestCallback(
                self, True, [VirusTotalApiRequestCallback.PARAM_RESOURCE]), False)

        logger.info("Registering request callback: {0}".format("url_scan"))
        self.add_request_callback(
            service, self.REQ_TOPIC_URL_SCAN,
            VirusTotalApiRequestCallback(
                self, False, [VirusTotalApiRequestCallback.PARAM_URL]), False)

        logger.info("Registering request callback: {0}".format("url_report"))
        self.add_request_callback(
            service, self.REQ_TOPIC_URL_REPORT,
            VirusTotalApiRequestCallback(
                self, False, [VirusTotalApiRequestCallback.PARAM_RESOURCE]), False)

        logger.info("Registering request callback: {0}".format("ipaddress_report"))
        self.add_request_callback(
            service, self.REQ_TOPIC_IP_ADDRESS_REPORT,
            VirusTotalApiRequestCallback(
                self, True, [VirusTotalApiRequestCallback.PARAM_IP]), False)

        logger.info("Registering request callback: {0}".format("domain_report"))
        self.add_request_callback(
            service, self.REQ_TOPIC_DOMAIN_REPORT,
            VirusTotalApiRequestCallback(
                self, True, [VirusTotalApiRequestCallback.PARAM_DOMAIN]), False)

        self.register_service(service)
