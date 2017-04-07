import logging
import requests

from dxlclient.callbacks import RequestCallback
from dxlclient.message import Response, ErrorResponse
from dxlbootstrap.util import MessageUtils


# Configure local logger
logger = logging.getLogger(__name__)


class VirusTotalApiRequestCallback(RequestCallback):
    """
    Request callback used to convert DXL requests to VirusTotal API invocations
    and send back a corresponding DXL response.
    """

    #: The resource request parameter
    PARAM_RESOURCE = "resource"
    #: The URL request parameter
    PARAM_URL = "url"
    #: The IP address request parameter
    PARAM_IP = "ip"
    #: The domain request parameter
    PARAM_DOMAIN = "domain"

    def __init__(self, app, is_get, required_params):
        """
        Constructor parameters:

        :param app: The application this handler is associated with
        :param is_get: Whether to use GET or POST when invoking the VirusTotal API method
        :param required_params: The list of required parameters for the VirusTotal API method
        """
        super(VirusTotalApiRequestCallback, self).__init__()
        self._app = app
        self._is_get = is_get
        self._required_params = required_params
        self._headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "gzip,  VirusTotal API DXL service library"
        }

    def _validate(self, req_dict):
        """
        Validates that required parameters are present in the specified
        dictionary

        :param req_dict: The request dictionary
        """
        if self._required_params:
            for param in self._required_params:
                if param not in req_dict:
                    raise Exception("Required parameter not specified: '{0}'".format(param))

    @staticmethod
    def _get_http_error_message(code):
        """
        Returns an error message for the specified HTTP response code

        :param code: The HTTP response code
        :return: The error message for the response code
        """
        if code is 204:
            return "VirusTotal API request rate limit exceeded."
        else:
            return None

    def on_request(self, request):
        """
        Invoked when a request message is received.

        :param request: The request message
        """
        # Handle request
        logger.info("Request received on topic: '{0}' with payload: '{1}'".format(
            request.destination_topic, MessageUtils.decode_payload(request)))

        try:
            # API URL
            api_url = self._app.VTAPI_URL_FORMAT.format(
                request.destination_topic[self._app.SERVICE_TYPE_LENGTH:])

            # Parameters
            params = MessageUtils.json_payload_to_dict(request)
            params["apikey"] = self._app.api_key

            # Validate parameters
            self._validate(params)

            # Invoke VirusTotal API
            if self._is_get:
                vtapi_response = requests.get(api_url, params=params, headers=self._headers)
            else:
                vtapi_response = requests.post(api_url, params=params, headers=self._headers)

            # Check HTTP response code
            status_code = vtapi_response.status_code
            if status_code != 200:
                vtapi_response.raise_for_status()
                http_message = self._get_http_error_message(status_code)
                if http_message:
                    raise Exception("VirusTotal error, {0} ({1})".format(http_message, str(status_code)))
                else:
                    raise Exception("VirusTotal error, HTTP response code: {0}".format(status_code))

            # Read the VirusTotal response dictionary
            vtapi_response_dict = vtapi_response.json()

            # Parse response from VirusTotal
            if (type(vtapi_response_dict) is dict) and ("response_code" in vtapi_response_dict):
                response_code = vtapi_response_dict["response_code"]
                if response_code != 1:
                    if "verbose_msg" in vtapi_response_dict:
                        raise Exception("VirusTotal error: '{0}' {1}"
                                        .format(vtapi_response_dict["verbose_msg"], response_code))
                    else:
                        raise Exception("VirusTotal error code: {0}".format(response_code))

                # Create response
                res = Response(request)

                # Set payload
                MessageUtils.dict_to_json_payload(res, vtapi_response_dict)

                # Send response
                self._app.client.send_response(res)
            else:
                # Empty response
                raise Exception("Empty response received from VirusTotal, are parameters correct?")

        except Exception as ex:
            logger.exception("Error handling request")
            err_message = str(ex)
            err_message = err_message.replace(self._app.api_key, "--api-key--")
            err_res = ErrorResponse(request, MessageUtils.encode(err_message))
            self._app.client.send_response(err_res)
