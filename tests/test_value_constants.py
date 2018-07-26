import os
from datetime import datetime

TEST_FOLDER = str(os.path.dirname(os.path.abspath(__file__)))
VT_SERVICE_CONFIG_FILENAME = TEST_FOLDER + "/dxlvtapiservice.config"

SAMPLE_API_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
RATE_EXCEED_SERVER_PATH = "/test/rate/exceed"
HTTP_ERROR_SERVER_PATH = "/test/http/error"

BASIC_SERVICE_RESPONSE = {'return': 'pong'}

RECEIVED_PARAMS_KEY = "received_params"

SAMPLE_DATE = datetime(2018, 5, 17, 23, 59, 59, 999999)

SAMPLE_DOMAIN = '027.ru'
SAMPLE_FILE = '7657fcb7d772448a6d8504e4b20168b8'
SAMPLE_IP = '90.156.201.27'
SAMPLE_URL = 'http://www.virustotal.com'

SAMPLE_DOMAIN_REPORT = {
    "BitDefender category": "parked",
    "Dr.Web category": "known infection source",
    "Forcepoint ThreatSeeker category": "web images",
    "Websense ThreatSeeker category": "uncategorized",
    "Webutation domain info": {
        "Adult content": "yes",
        "Safety score": 40,
        "Verdict": "malicious"
    },
    "categories": [
        "parked",
        "web images"
    ],
    "detected_downloaded_samples": [
        {
            "date": "2013-06-20 18:51:30",
            "positives": 2,
            "sha256": "cd8553d9b24574467f381d13c7e0e1eb1e58d677b9484bd05b9c690377813e54",
            "total": 46
        }
    ],
    "detected_referrer_samples": [],
    "detected_urls": [
        {
            "positives": 2,
            "scan_date": "2018-06-13 19:34:58",
            "total": 67,
            "url": "http://027.ru/15.jpg"
        }
    ],
    "domain_siblings": [],
    "resolutions": [
        {
            "ip_address": "185.53.177.31",
            "last_resolved": "2018-06-13 19:35:02"
        }
    ],
    "response_code": 1,
    "subdomains": [
        "test.027.ru",
        "www.027.ru"
    ],
    "undetected_downloaded_samples": [
        {
            "date": "2018-01-14 22:34:24",
            "positives": 0,
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "total": 70
        }
    ],
    "undetected_referrer_samples": [
        {
            "date": "2018-03-04 16:38:06",
            "positives": 0,
            "sha256": "ce08cf22949b6b6fcd4e61854ce810a4f9ee04529340dd077fa354d759dc7a95",
            "total": 66
        }
    ],
    "undetected_urls": [],
    "verbose_msg": "Domain found in dataset",
    "whois": ""
             "domain: 027.RU\n"
             "nserver: ns1.nevsruev.ru.\n"
             "nserver: ns2.nevsruev.ru.\n"
             "state: REGISTERED, DELEGATED, VERIFIED\n"
             "registrar: RU-CENTER-RU\n"
             "created: 2005-12-08T21:00:00Z\n"
             "paid-till: 2018-12-08T21:00:00Z\n"
             "source: TCI\n"
             "Last updated on 2018-06-03T20:01:30Z",
    "whois_timestamp": 1528056145
}

SAMPLE_FILE_REPORT = {
    "md5": "7657fcb7d772448a6d8504e4b20168b8",
    "permalink": "https://www.virustotal.com/url/test/",
    "positives": 64,
    "resource": "7657fcb7d772448a6d8504e4b20168b8",
    "response_code": 1,
    "scan_date": "2018-07-16 12:58:04",
    "scan_id": "54bc950d46a0d1aa72048a17c8275743209e6c17bdacfc4cb9601c9ce3ec9a71-1531745884",
    "scans": {
        "AVG": {
            "detected": True,
            "result": "Win32:Kryptik-JOV [Trj]",
            "update": "20180716",
            "version": "18.4.3895.0"
        },
        "McAfee": {
            "detected": True,
            "result": "PWS-Zbot.gen.cy",
            "update": "20180716",
            "version": "6.0.6.653"
        },
    },
    "sha1": "84c7201f7e59cb416280fd69a2e7f2e349ec8242",
    "sha256": "54bc950d46a0d1aa72048a17c8275743209e6c17bdacfc4cb9601c9ce3ec9a71",
    "total": 68,
    "verbose_msg": "Scan finished, information embedded"
}

SAMPLE_FILE_RESCAN = {
    "permalink": "https://www.virustotal.com/url/test/",
    "resource": "7657fcb7d772448a6d8504e4b20168b8",
    "response_code": 1,
    "scan_id": "54bc950d46a0d1aa72048a17c8275743209e6c17bdacfc4cb9601c9ce3ec9a71-1531765312",
    "sha256": "54bc950d46a0d1aa72048a17c8275743209e6c17bdacfc4cb9601c9ce3ec9a71"
}

SAMPLE_IP_ADDRESS_REPORT = {
    "as_owner": ".masterhost autonomous system",
    "asn": "25532",
    "country": "RU",
    "detected_downloaded_samples": [
        {
            "date": "2017-10-12 01:34:54",
            "positives": 27,
            "sha256": "24da30bc528fc99eea326e40405422e6077793aa439c6da38f6103286155621b",
            "total": 50
        }
    ],
    "detected_urls": [
        {
            "positives": 1,
            "scan_date": "2018-01-25 13:03:34",
            "total": 66,
            "url": "http://www.rusbiscuit.ru/"
        }
    ],
    "resolutions": [
        {
            "hostname": "027.ru",
            "last_resolved": "2013-04-01 00:00:00"
        }
    ],
    "response_code": 1,
    "undetected_downloaded_samples": [
        {
            "date": "2016-06-22 00:03:00",
            "positives": 0,
            "sha256": "e822fe8750307c8a294b72280aabfd8e4d2ca0f3958f860b55b44624e88b558d",
            "total": 57
        }
    ],
    "undetected_urls": [
        [
            "http://mastersite.ru/",
            "176dbc4071013fb13141ccdc2fbab5f2df695636e16ed52159f8b60d2c3a78ff",
            0,
            63,
            "2017-10-13 03:42:00"
        ]
    ],
    "verbose_msg": "IP address in dataset"
}

SAMPLE_URL_REPORT = {
    "filescan_id": None,
    "permalink": "https://www.virustotal.com/url/test/",
    "positives": 0,
    "resource": "http://www.virustotal.com",
    "response_code": 1,
    "scan_date": "2018-07-16 13:41:56",
    "scan_id": "1db0ad7dbcec0676710ea0eaacd35d5e471d3e11944d53bcbd31f0cbd11bce31-1531748516",
    "scans": {
        "ADMINUSLabs": {
            "detected": False,
            "result": "clean site"
        }
    },
    "total": 68,
    "url": "http://www.virustotal.com/",
    "verbose_msg": "Scan finished, scan information embedded in this object"
}

SAMPLE_URL_SCAN = {
    "permalink": "https://www.virustotal.com/url/test/",
    "resource": "http://www.virustotal.com/",
    "response_code": 1,
    "scan_date": "2018-07-16 18:33:50",
    "scan_id": "1db0ad7dbcec0676710ea0eaacd35d5e471d3e11944d53bcbd31f0cbd11bce31-1531766030",
    "url": "http://www.virustotal.com/",
    "verbose_msg": "Scan request successfully queued, come back later for the report"
}
