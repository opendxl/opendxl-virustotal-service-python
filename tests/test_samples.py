from dxlvtapiservice import VirusTotalApiService
from tests.mock_vthttpserver import MockServerRunner
from tests.test_base import *
from tests.test_service import create_vtservice_configfile
from tests.test_value_constants import *


def configure_vt_service(dxl_client, port):

    create_vtservice_configfile(
        config_file_name=VT_SERVICE_CONFIG_FILENAME
    )

    vt_service = VirusTotalApiService(TEST_FOLDER)
    vt_service._dxl_client = dxl_client

    vt_service.VTAPI_URL_FORMAT = "http://127.0.0.1:" \
          + str(port) \
          + "/vtapi/v2{0}"

    vt_service._load_configuration()
    vt_service.on_register_services()

    return vt_service


class TestSamples(BaseClientTest):

    def test_domainreport_example(self):
        # Modify sample file to include necessary sample data
        sample_filename = self.BASIC_FOLDER + "/basic_domain_report_example.py"

        with self.create_client(max_retries=0) as dxl_client:
            with MockServerRunner() as mock_server:
                dxl_client.connect()

                configure_vt_service(dxl_client, mock_server.mock_server_port)

                mock_print = BaseClientTest.run_sample(sample_filename)

                mock_print.assert_any_call(
                    StringDoesNotContain("Error")
                )

                # Validate whois_timestamp from report
                mock_print.assert_any_call(
                    StringContains(
                        str(SAMPLE_DOMAIN_REPORT["whois_timestamp"])
                    )
                )

                dxl_client.disconnect()


    def test_filereport_example(self):
        # Modify sample file to include necessary sample data
        sample_filename = self.BASIC_FOLDER + "/basic_file_report_example.py"

        with self.create_client(max_retries=0) as dxl_client:
            with MockServerRunner() as mock_server:
                dxl_client.connect()

                configure_vt_service(dxl_client, mock_server.mock_server_port)

                mock_print = BaseClientTest.run_sample(sample_filename)

                mock_print.assert_any_call(
                    StringDoesNotContain("Error")
                )

                # Validate md5 from report
                mock_print.assert_any_call(
                    StringContains(
                        str(SAMPLE_FILE_REPORT["md5"])
                    )
                )

                dxl_client.disconnect()


    def test_filerescan_example(self):
        # Modify sample file to include necessary sample data
        sample_filename = self.BASIC_FOLDER + "/basic_file_rescan_example.py"

        with self.create_client(max_retries=0) as dxl_client:
            with MockServerRunner() as mock_server:
                dxl_client.connect()

                configure_vt_service(dxl_client, mock_server.mock_server_port)

                mock_print = BaseClientTest.run_sample(sample_filename)

                mock_print.assert_any_call(
                    StringDoesNotContain("Error")
                )

                # Validate scan_id from report
                mock_print.assert_any_call(
                    StringContains(
                        str(SAMPLE_FILE_RESCAN["scan_id"])
                    )
                )

                dxl_client.disconnect()


    def test_ipreport_example(self):
        # Modify sample file to include necessary sample data
        sample_filename = self.BASIC_FOLDER + "/basic_ip_address_report_example.py"

        with self.create_client(max_retries=0) as dxl_client:
            with MockServerRunner() as mock_server:
                dxl_client.connect()

                configure_vt_service(dxl_client, mock_server.mock_server_port)

                mock_print = BaseClientTest.run_sample(sample_filename)

                mock_print.assert_any_call(
                    StringDoesNotContain("Error")
                )

                # Validate asn from report
                mock_print.assert_any_call(
                    StringContains(
                        str(SAMPLE_IP_ADDRESS_REPORT["asn"])
                    )
                )

                dxl_client.disconnect()


    def test_urlreport_example(self):
        # Modify sample file to include necessary sample data
        sample_filename = self.BASIC_FOLDER + "/basic_url_report_example.py"

        with self.create_client(max_retries=0) as dxl_client:
            with MockServerRunner() as mock_server:
                dxl_client.connect()

                configure_vt_service(dxl_client, mock_server.mock_server_port)

                mock_print = BaseClientTest.run_sample(sample_filename)

                mock_print.assert_any_call(
                    StringDoesNotContain("Error")
                )

                # Validate scan_id from report
                mock_print.assert_any_call(
                    StringContains(
                        str(SAMPLE_URL_REPORT["scan_id"])
                    )
                )

                dxl_client.disconnect()


    def test_urlscan_example(self):
        # Modify sample file to include necessary sample data
        sample_filename = self.BASIC_FOLDER + "/basic_url_scan_example.py"

        with self.create_client(max_retries=0) as dxl_client:
            with MockServerRunner() as mock_server:
                dxl_client.connect()

                configure_vt_service(dxl_client, mock_server.mock_server_port)

                mock_print = BaseClientTest.run_sample(sample_filename)

                mock_print.assert_any_call(
                    StringDoesNotContain("Error")
                )

                # Validate scan_id from report
                mock_print.assert_any_call(
                    StringContains(
                        str(SAMPLE_URL_SCAN["scan_id"])
                    )
                )

                dxl_client.disconnect()
