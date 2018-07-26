import socket
import re

try: #Python 3
    from http.server import SimpleHTTPRequestHandler
    from socketserver import TCPServer
    import urllib.parse as urlparse
except ImportError: #Python 2.7
    from SimpleHTTPServer import  SimpleHTTPRequestHandler
    from SocketServer import TCPServer
    import urlparse


from threading import Thread

import requests

from dxlbootstrap.util import MessageUtils
from dxlvtapiservice import VirusTotalApiService
from dxlvtapiservice.requesthandlers import VirusTotalApiRequestCallback
from tests.test_value_constants import *

TEST_FOLDER = str(os.path.dirname(os.path.abspath(__file__)).replace("\\", "/"))
MOCK_EPOHTTPSERVER_CERTNAME = TEST_FOLDER + "/client.crt"
MOCK_EPOHTTPSERVER_KEYNAME = TEST_FOLDER + "/client.key"


def get_free_port():
    stream_socket = socket.socket(socket.AF_INET, type=socket.SOCK_STREAM)
    stream_socket.bind(('localhost', 0))
    address, port = stream_socket.getsockname()
    stream_socket.close()

    return address, port


class MockVtServerRequestHandler(SimpleHTTPRequestHandler):

    #pylint: disable=line-too-long
    BASE_PATTERN = "/vtapi/v2{0}"

    FILE_RESCAN_PATTERN = re.compile(
        BASE_PATTERN.format(
            VirusTotalApiService.REQ_TOPIC_FILE_RESCAN[VirusTotalApiService.SERVICE_TYPE_LENGTH:]
        )
    )
    FILE_REPORT_PATTERN = re.compile(
        BASE_PATTERN.format(
            VirusTotalApiService.REQ_TOPIC_FILE_REPORT[VirusTotalApiService.SERVICE_TYPE_LENGTH:]
        )
    )
    URL_SCAN_PATTERN = re.compile(
        BASE_PATTERN.format(
            VirusTotalApiService.REQ_TOPIC_URL_SCAN[VirusTotalApiService.SERVICE_TYPE_LENGTH:]
        )
    )
    URL_REPORT_PATTERN = re.compile(
        BASE_PATTERN.format(
            VirusTotalApiService.REQ_TOPIC_URL_REPORT[VirusTotalApiService.SERVICE_TYPE_LENGTH:]
        )
    )
    IP_REPORT_PATTERN = re.compile(
        BASE_PATTERN.format(
            VirusTotalApiService.REQ_TOPIC_IP_ADDRESS_REPORT[VirusTotalApiService.SERVICE_TYPE_LENGTH:]
        )
    )
    DOMAIN_REPORT_PATTERN = re.compile(
        BASE_PATTERN.format(
            VirusTotalApiService.REQ_TOPIC_DOMAIN_REPORT[VirusTotalApiService.SERVICE_TYPE_LENGTH:]
        )
    )
    RATE_EXCEED_PATTERN = re.compile(RATE_EXCEED_SERVER_PATH)
    HTTP_ERROR_PATTERN = re.compile(HTTP_ERROR_SERVER_PATH)


    def do_GET(self):

        response_code = requests.codes.ok #pylint: disable=no-member

        parsed_url = urlparse.urlparse(self.path)

        parsed_api_key = \
            urlparse.parse_qs(parsed_url.query)[VirusTotalApiService.GENERAL_API_KEY_CONFIG_PROP.lower()][0]

        if parsed_api_key == SAMPLE_API_KEY:
            #if re.search('')
            #   response_content = self.rate_limit_exceeded(re)
            if re.search(self.DOMAIN_REPORT_PATTERN, self.path):
                response_content = self.domain_report_cmd(parsed_url)

            elif re.search(self.FILE_REPORT_PATTERN, self.path):
                response_content = self.file_report_cmd(parsed_url)

            elif re.search(self.IP_REPORT_PATTERN, self.path):
                response_content = self.ip_report_cmd(parsed_url)

            elif re.search(self.RATE_EXCEED_PATTERN, self.path):
                response_code = requests.codes.no_content #pylint: disable=no-member
                response_content = ""

            elif re.search(self.HTTP_ERROR_PATTERN, self.path):
                response_code = requests.codes.internal_server_error #pylint: disable=no-member
                response_content = "500 - Internal Server Error"

            else:
                response_content = self.unknown_call(self.path)
        else:
            response_content = self.bad_param(
                VirusTotalApiService.GENERAL_API_KEY_CONFIG_PROP,
                parsed_api_key
            )

        self.send_response(response_code, response_content)

        self.send_header('Content-Type', 'text/plain; charset=utf-8', )
        self.end_headers()

        self.wfile.write(response_content.encode('utf-8'))


    def do_POST(self): #pylint: disable=invalid-name
        parsed_url = urlparse.urlparse(self.path)

        # pylint: disable=line-too-long
        parsed_api_key = \
            urlparse.parse_qs(parsed_url.query)[VirusTotalApiService.GENERAL_API_KEY_CONFIG_PROP.lower()][0]

        if parsed_api_key == SAMPLE_API_KEY:
            if re.search(self.FILE_RESCAN_PATTERN, self.path):
                response_content = self.file_rescan_cmd(parsed_url)

            elif re.search(self.URL_REPORT_PATTERN, self.path):
                response_content = self.url_report_cmd(parsed_url)

            elif re.search(self.URL_SCAN_PATTERN, self.path):
                response_content = self.url_scan_cmd(parsed_url)

            else:
                response_content = self.unknown_call(self.path)
        else:
            response_content = self.bad_param(
                VirusTotalApiService.GENERAL_API_KEY_CONFIG_PROP,
                parsed_api_key
            )

        self.send_response(requests.codes.ok, response_content) #pylint: disable=no-member

        self.send_header('Content-Type', 'text/plain; charset=utf-8', )
        self.end_headers()

        self.wfile.write(response_content.encode('utf-8'))


    def domain_report_cmd(self, parsed_url):
        domain = \
            urlparse.parse_qs(parsed_url.query)[VirusTotalApiRequestCallback.PARAM_DOMAIN][0]
        if domain == SAMPLE_DOMAIN:
            return MessageUtils.dict_to_json(SAMPLE_DOMAIN_REPORT, pretty_print=False)
        return self.bad_param(VirusTotalApiRequestCallback.PARAM_DOMAIN, domain)


    def file_report_cmd(self, parsed_url):
        resource = \
            urlparse.parse_qs(parsed_url.query)[VirusTotalApiRequestCallback.PARAM_RESOURCE][0]
        if resource == SAMPLE_FILE:
            return MessageUtils.dict_to_json(SAMPLE_FILE_REPORT, pretty_print=False)
        return self.bad_param(VirusTotalApiRequestCallback.PARAM_RESOURCE, resource)


    def file_rescan_cmd(self, parsed_url):
        resource = \
            urlparse.parse_qs(parsed_url.query)[VirusTotalApiRequestCallback.PARAM_RESOURCE][0]
        if resource == SAMPLE_FILE:
            return MessageUtils.dict_to_json(SAMPLE_FILE_RESCAN, pretty_print=False)
        return self.bad_param(VirusTotalApiRequestCallback.PARAM_RESOURCE, resource)


    def ip_report_cmd(self, parsed_url):
        ip_address = \
            urlparse.parse_qs(parsed_url.query)[VirusTotalApiRequestCallback.PARAM_IP][0]
        if ip_address == SAMPLE_IP:
            return MessageUtils.dict_to_json(SAMPLE_IP_ADDRESS_REPORT, pretty_print=False)
        return self.bad_param(VirusTotalApiRequestCallback.PARAM_IP, ip_address)


    def url_report_cmd(self, parsed_url):
        url = \
            urlparse.parse_qs(parsed_url.query)[VirusTotalApiRequestCallback.PARAM_RESOURCE][0]
        if url == SAMPLE_URL:
            return MessageUtils.dict_to_json(SAMPLE_URL_REPORT, pretty_print=False)
        return self.bad_param(VirusTotalApiRequestCallback.PARAM_RESOURCE, url)


    def url_scan_cmd(self, parsed_url):
        url = \
            urlparse.parse_qs(parsed_url.query)[VirusTotalApiRequestCallback.PARAM_URL][0]
        if url == SAMPLE_URL:
            return MessageUtils.dict_to_json(SAMPLE_URL_SCAN, pretty_print=False)
        return self.bad_param(VirusTotalApiRequestCallback.PARAM_URL, url)


    # Needs to return ERROR 204 HEADER!
    #@staticmethod
    #def rate_limit_exceeded(cmd_string):
    #    # Needs to return ERROR 204 HEADER!
    #    return None


    @staticmethod
    def bad_param(param_name, param_val):
        return MessageUtils.dict_to_json(
            {
                "unit_test_bad_param_name": param_name,
                "unit_test_bad_param_val": param_val
            },
            pretty_print=False
        )

    @staticmethod
    def unknown_call(path):
        return MessageUtils.dict_to_json(
            {
                "unit_test_error_unknown_api": path
            },
            pretty_print=False
        )


class MockServerRunner(object):

    def __init__(self):
        self.server_name = "mockvtserver"
        self.mock_server_port = 0
        self.mock_server = None
        self.mock_server_address = ""

    def __enter__(self):
        self.mock_server_address, self.mock_server_port = get_free_port()
        self.mock_server = TCPServer(
            ('localhost', self.mock_server_port),
            MockVtServerRequestHandler
        )
        #self.mock_server.socket = ssl.wrap_socket(
        #    self.mock_server.socket,
        #    certfile=MOCK_EPOHTTPSERVER_CERTNAME,
        #    keyfile=MOCK_EPOHTTPSERVER_KEYNAME,
        #    server_side=True
        #)

        mock_server_thread = Thread(target=self.mock_server.serve_forever)
        mock_server_thread.setDaemon(True)
        mock_server_thread.start()

        return self


    def __exit__(self, exc_type, exc_val, exc_tb):
        self.mock_server.shutdown()
