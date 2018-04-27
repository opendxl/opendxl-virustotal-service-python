Basic File Report Example
=========================

This sample invokes and displays the results of a VirusTotal "file report" via DXL.

For more information see:
    https://www.virustotal.com/en/documentation/public-api/#getting-file-scans

Prerequisites
*************
* The samples configuration step has been completed (see :doc:`sampleconfig`)
* The VirusTotal API DXL service is running (see :doc:`running`)

Running
*******

To run this sample execute the ``sample/basic/basic_file_report_example.py`` script as follows:

    .. parsed-literal::

        python sample/basic/basic_file_report_example.py

The output should appear similar to the following:

    .. code-block:: python

        {
            "md5": "7657fcb7d772448a6d8504e4b20168b8",
            "permalink": "https://www.virustotal.com/file/54bc950d46a0d1aa72048a17c8275743209e6c17bdacfc4cb9601c9ce3ec9a71/analysis/1491516000/",
            "positives": 61,
            "resource": "7657fcb7d772448a6d8504e4b20168b8",
            "response_code": 1,
            "scan_date": "2017-04-06 22:00:00",
            "scan_id": "54bc950d46a0d1aa72048a17c8275743209e6c17bdacfc4cb9601c9ce3ec9a71-1491516000",
            "scans": {
                "ALYac": {
                    "detected": true,
                    "result": "Gen:Variant.Kazy.8782",
                    "update": "20170406",
                    "version": "1.0.1.9"
                },
                "AVG": {
                    "detected": true,
                    "result": "SHeur3.BNDF",
                    "update": "20170406",
                    "version": "16.0.0.4769"
                },

                ...

                "nProtect": {
                    "detected": true,
                    "result": "Trojan-Spy/W32.ZBot.109056.AR",
                    "update": "20170406",
                    "version": "2017-04-06.02"
                }
            },
            "sha1": "84c7201f7e59cb416280fd69a2e7f2e349ec8242",
            "sha256": "54bc950d46a0d1aa72048a17c8275743209e6c17bdacfc4cb9601c9ce3ec9a71",
            "total": 62,
            "verbose_msg": "Scan finished, information embedded"
        }

The scan results from the various providers are listed.

Details
*******

The majority of the sample code is shown below:

    .. code-block:: python

        # Create the client
        with DxlClient(config) as client:

            # Connect to the fabric
            client.connect()

            logger.info("Connected to DXL fabric.")

            # Invoke 'file report' method on service
            request_topic = "/opendxl-virustotal/service/vtapi/file/report"
            req = Request(request_topic)
            MessageUtils.dict_to_json_payload(req, {"resource": "7657fcb7d772448a6d8504e4b20168b8"})
            res = client.sync_request(req, timeout=30)

            if res.message_type != Message.MESSAGE_TYPE_ERROR:
                # Display results
                res_dict = MessageUtils.json_payload_to_dict(res)
                print(MessageUtils.dict_to_json(res_dict, pretty_print=True))
            else:
                print("Error invoking service with topic '{0}': {1} ({2})".format(
                    request_topic, res.error_message, res.error_code))


After connecting to the DXL fabric, a `request message` is created with a topic that targets the "file report" method
of the VirusTotal API DXL service.

The next step is to set the `payload` of the request message. The contents of the payload include the `resource`
to report on (in this case, an MD5 hash).

From the VirusTotal `retrieving file scan reports documentation <https://www.virustotal.com/en/documentation/public-api/#getting-file-scans>`_:

    `"A md5/sha1/sha256 hash will retrieve the most recent report on a given sample. You may also specify a scan_id
    (sha256-timestamp as returned by the file upload API) to access a specific report. You can also specify a CSV
    list made up of a combination of hashes and scan_ids (up to 4 items with the standard request rate), this allows
    you to perform a batch request with one single call."`

The final step is to perform a `synchronous request` via the DXL fabric. If the `response message` is not an error
its contents are displayed.



