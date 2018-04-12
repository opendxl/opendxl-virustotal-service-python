Basic Domain Report Example
===========================

This sample invokes and displays the results of a VirusTotal "domain report" via DXL.

For more information see:
    https://www.virustotal.com/en/documentation/public-api/#getting-domain-reports

Prerequisites
*************
* The samples configuration step has been completed (see :doc:`sampleconfig`)
* The VirusTotal API DXL service is running (see :doc:`running`)

Running
*******

To run this sample execute the ``sample/basic/basic_domain_report_example.py`` script as follows:

    .. parsed-literal::

        python sample/basic/basic_domain_report_example.py

The output should appear similar to the following:

    .. code-block:: python

        {
            "BitDefender category": "parked",
            "Dr.Web category": "known infection source",
            "Websense ThreatSeeker category": "uncategorized",
            "Webutation domain info": {
                "Adult content": "yes",
                "Safety score": 40,
                "Verdict": "malicious"
            },
            "categories": [
                "parked",
                "uncategorized"
            ],
            "detected_downloaded_samples": [
                {
                    "date": "2013-06-20 18:51:30",
                    "positives": 2,
                    "sha256": "cd8553d9b24574467f381d13c7e0e1eb1e58d677b9484bd05b9c690377813e54",
                    "total": 46
                }
            ],
            "detected_urls": [
                {
                    "positives": 1,
                    "scan_date": "2017-03-31 00:16:29",
                    "total": 64,
                    "url": "http://027.ru/"
                },

                ...

                {
                    "positives": 2,
                    "scan_date": "2015-02-18 08:54:52",
                    "total": 62,
                    "url": "http://027.ru/index.html"
                }
            ],
            "domain_siblings": [],
            "resolutions": [
                {
                    "ip_address": "185.53.177.31",
                    "last_resolved": "2017-02-02 00:00:00"
                },

                ...

                {
                    "ip_address": "90.156.201.97",
                    "last_resolved": "2013-06-20 00:00:00"
                }
            ],
            "response_code": 1,
            "subdomains": [
                "www.027.ru"
            ],
            "undetected_referrer_samples": [
                {
                    "positives": 0,
                    "sha256": "b8f5db667431d02291eeec61cf9f0c3d7af00798d0c2d676fde0efb0cedb7741",
                    "total": 53
                }
            ],

            ...
        }


The received results are displayed.

Details
*******

The majority of the sample code is shown below:

    .. code-block:: python

        # Create the client
        with DxlClient(config) as client:

            # Connect to the fabric
            client.connect()

            logger.info("Connected to DXL fabric.")

            # Invoke 'domain report' method on service
            request_topic = "/opendxl-virustotal/service/vtapi/domain/report"
            req = Request(request_topic)
            MessageUtils.dict_to_json_payload(req, {"domain": "027.ru"})
            res = client.sync_request(req, timeout=30)

            if res.message_type != Message.MESSAGE_TYPE_ERROR:
                # Display results
                res_dict = MessageUtils.json_payload_to_dict(res)
                print(MessageUtils.dict_to_json(res_dict, pretty_print=True))
            else:
                print("Error invoking service with topic '{0}': {1} ({2})".format(
                    request_topic, res.error_message, res.error_code))


After connecting to the DXL fabric, a `request message` is created with a topic that targets the "domain report" method
of the VirusTotal API DXL service.

The next step is to set the `payload` of the request message. The contents of the payload include the `domain`
to report on.

The final step is to perform a `synchronous request` via the DXL fabric. If the `response message` is not an error
its contents are displayed.



