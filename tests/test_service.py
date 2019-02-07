import sys
from configparser import ConfigParser
from dxlbootstrap.util import MessageUtils
from dxlclient import Request, Response
from dxlvtapiservice import VirusTotalApiService
from dxlvtapiservice.requesthandlers import VirusTotalApiRequestCallback

from tests.test_base import BaseClientTest
from tests.test_value_constants import *
from tests.mock_vthttpserver import MockServerRunner

sys.path.append(
    os.path.dirname(os.path.abspath(__file__)) + "/../.."
)

def create_vtservice_configfile(config_file_name):
    config = ConfigParser()

    config['General'] = {'apiKey': SAMPLE_API_KEY}

    with open(config_file_name, 'w') as config_file:
        config.write(config_file)


class TestConfiguration(BaseClientTest):

    def test_loadconfig(self):

        create_vtservice_configfile(
            config_file_name=VT_SERVICE_CONFIG_FILENAME,
        )

        vt_service = VirusTotalApiService(TEST_FOLDER)
        vt_service._load_configuration()

        self.assertEqual(vt_service.api_key, SAMPLE_API_KEY)

        os.remove(VT_SERVICE_CONFIG_FILENAME)


    def test_registerservices(self):
        with MockServerRunner():

            create_vtservice_configfile(
                config_file_name=VT_SERVICE_CONFIG_FILENAME
            )

            with BaseClientTest.create_client(max_retries=0) as dxl_client:
                dxl_client.connect()

                vt_service = VirusTotalApiService(TEST_FOLDER)
                vt_service._dxl_client = dxl_client

                vt_service._load_configuration()
                vt_service.on_register_services()

                self.assertTrue(len(vt_service._services) > 0)

                expected_vt_topics = {
                    VirusTotalApiService.REQ_TOPIC_FILE_REPORT,
                    VirusTotalApiService.REQ_TOPIC_FILE_RESCAN,
                    VirusTotalApiService.REQ_TOPIC_URL_SCAN,
                    VirusTotalApiService.REQ_TOPIC_URL_REPORT,
                    VirusTotalApiService.REQ_TOPIC_IP_ADDRESS_REPORT,
                    VirusTotalApiService.REQ_TOPIC_DOMAIN_REPORT
                }

                for expected_topic in expected_vt_topics:
                    self.assertIn(expected_topic, vt_service._services[0].topics)


class TestVtRequestCallback(BaseClientTest):

    def test_callback_domainreport(self):
        with MockServerRunner() as server_runner, \
                VirusTotalApiService(TEST_FOLDER) as vt_service:

            vt_service.VTAPI_URL_FORMAT = "http://127.0.0.1:" \
                                          + str(server_runner.mock_server_port) \
                                          + "/vtapi/v2{0}"
            vt_service.run()

            request_topic = VirusTotalApiService.REQ_TOPIC_DOMAIN_REPORT
            req = Request(request_topic)
            MessageUtils.dict_to_json_payload(
                req,
                {
                    VirusTotalApiRequestCallback.PARAM_DOMAIN: SAMPLE_DOMAIN
                }
            )

            res = vt_service._dxl_client.sync_request(req, timeout=30)
            res_dict = MessageUtils.json_payload_to_dict(res)

            self.assertDictEqual(
                SAMPLE_DOMAIN_REPORT,
                res_dict
            )


    def test_callback_filereport(self):

        with MockServerRunner() as server_runner, \
                VirusTotalApiService(TEST_FOLDER) as vt_service:

            vt_service.VTAPI_URL_FORMAT = "http://127.0.0.1:" \
                                          + str(server_runner.mock_server_port) \
                                          + "/vtapi/v2{0}"
            vt_service.run()

            request_topic = VirusTotalApiService.REQ_TOPIC_FILE_REPORT
            req = Request(request_topic)
            MessageUtils.dict_to_json_payload(
                req,
                {
                    VirusTotalApiRequestCallback.PARAM_RESOURCE: SAMPLE_FILE
                }
            )

            res = vt_service._dxl_client.sync_request(req, timeout=30)
            res_dict = MessageUtils.json_payload_to_dict(res)

            self.assertDictEqual(
                SAMPLE_FILE_REPORT,
                res_dict
            )


    def test_callback_filerescan(self):
        with MockServerRunner() as server_runner, \
            VirusTotalApiService(TEST_FOLDER) as vt_service:

            vt_service.VTAPI_URL_FORMAT = "http://127.0.0.1:" \
                                          + str(server_runner.mock_server_port) \
                                          + "/vtapi/v2{0}"
            vt_service.run()

            request_topic = VirusTotalApiService.REQ_TOPIC_FILE_RESCAN
            req = Request(request_topic)
            MessageUtils.dict_to_json_payload(
                req,
                {
                    VirusTotalApiRequestCallback.PARAM_RESOURCE: SAMPLE_FILE
                }
            )

            res = vt_service._dxl_client.sync_request(req, timeout=30)
            res_dict = MessageUtils.json_payload_to_dict(res)

            self.assertDictEqual(
                SAMPLE_FILE_RESCAN,
                res_dict
            )


    def test_callback_ipreport(self):
        with MockServerRunner() as server_runner, \
            VirusTotalApiService(TEST_FOLDER) as vt_service:

            vt_service.VTAPI_URL_FORMAT = "http://127.0.0.1:" \
                                          + str(server_runner.mock_server_port) \
                                          + "/vtapi/v2{0}"
            vt_service.run()

            request_topic = VirusTotalApiService.REQ_TOPIC_IP_ADDRESS_REPORT
            req = Request(request_topic)
            MessageUtils.dict_to_json_payload(
                req,
                {
                    VirusTotalApiRequestCallback.PARAM_IP: SAMPLE_IP
                }
            )

            res = vt_service._dxl_client.sync_request(req, timeout=30)
            res_dict = MessageUtils.json_payload_to_dict(res)

            self.assertDictEqual(
                SAMPLE_IP_ADDRESS_REPORT,
                res_dict
            )


    def test_callback_urlreport(self):
        with MockServerRunner() as server_runner, \
            VirusTotalApiService(TEST_FOLDER) as vt_service:

            vt_service.VTAPI_URL_FORMAT = "http://127.0.0.1:" \
                                          + str(server_runner.mock_server_port) \
                                          + "/vtapi/v2{0}"
            vt_service.run()

            request_topic = VirusTotalApiService.REQ_TOPIC_URL_REPORT
            req = Request(request_topic)
            MessageUtils.dict_to_json_payload(
                req,
                {
                    VirusTotalApiRequestCallback.PARAM_RESOURCE: SAMPLE_URL
                }
            )

            res = vt_service._dxl_client.sync_request(req, timeout=30)
            res_dict = MessageUtils.json_payload_to_dict(res)

            self.assertDictEqual(
                SAMPLE_URL_REPORT,
                res_dict
            )


    def test_callback_urlscan(self):
        with MockServerRunner() as server_runner, \
            VirusTotalApiService(TEST_FOLDER) as vt_service:

            vt_service.VTAPI_URL_FORMAT = "http://127.0.0.1:" \
                                          + str(server_runner.mock_server_port) \
                                          + "/vtapi/v2{0}"
            vt_service.run()

            request_topic = VirusTotalApiService.REQ_TOPIC_URL_SCAN
            req = Request(request_topic)
            MessageUtils.dict_to_json_payload(
                req,
                {
                    VirusTotalApiRequestCallback.PARAM_URL: SAMPLE_URL
                }
            )

            res = vt_service._dxl_client.sync_request(req, timeout=30)
            res_dict = MessageUtils.json_payload_to_dict(res)

            self.assertDictEqual(
                SAMPLE_URL_SCAN,
                res_dict
            )


    def test_error_exceedrate(self):
        with MockServerRunner() as server_runner, \
            VirusTotalApiService(TEST_FOLDER) as vt_service:

            vt_service.VTAPI_URL_FORMAT = "http://127.0.0.1:" \
                                              + str(server_runner.mock_server_port) \
                                              + RATE_EXCEED_SERVER_PATH
            vt_service.run()

            request_topic = VirusTotalApiService.REQ_TOPIC_DOMAIN_REPORT
            req = Request(request_topic)
            MessageUtils.dict_to_json_payload(
                req,
                {
                    VirusTotalApiRequestCallback.PARAM_DOMAIN: SAMPLE_DOMAIN
                }
            )


            res = vt_service._dxl_client.sync_request(req, timeout=30)

            self.assertEqual(res.message_type, Response.MESSAGE_TYPE_ERROR)
            self.assertIn(
                "VirusTotal error, VirusTotal API request rate limit exceeded. (204)",
                res._error_message
            )


    def test_error_httperror(self):
        with MockServerRunner() as server_runner, \
            VirusTotalApiService(TEST_FOLDER) as vt_service:

            vt_service.VTAPI_URL_FORMAT = "http://127.0.0.1:" \
                                          + str(server_runner.mock_server_port) \
                                          + HTTP_ERROR_SERVER_PATH
            vt_service.run()

            request_topic = VirusTotalApiService.REQ_TOPIC_DOMAIN_REPORT
            req = Request(request_topic)
            MessageUtils.dict_to_json_payload(
                req,
                {
                    VirusTotalApiRequestCallback.PARAM_DOMAIN: SAMPLE_DOMAIN
                }
            )

            res = vt_service._dxl_client.sync_request(req, timeout=30)

            self.assertEqual(res.message_type, Response.MESSAGE_TYPE_ERROR)
            self.assertIn(
                "500 Server Error: 500 - Internal Server Error for url: ",
                res._error_message
            )
