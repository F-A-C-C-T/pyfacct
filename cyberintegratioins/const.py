# -*- encoding: utf-8 -*-
"""
Copyright (c) 2023 - present by Group-IB
"""
class TechnicalConsts(object):
    library_name = "cyberintegrations"
    library_version = "0.6.2"


class RequestConsts(object):
    API_URL = 'https://tap.group-ib.com/api/v2/'
    API_URL_DRP = 'https://drp.group-ib.com/client_api/'
    HEADERS = {
        "Accept": "*/*",
        "User-Agent": f"cyberintegrations/{TechnicalConsts.library_version}"
    }

    STATUS_CODE_MSGS = {
        301: "Verify that your public IP is whitelisted by Group-IB.",
        302: "Verify that your public IP is whitelisted by Group-IB.",
        400: "Bad Credentials or Wrong request. The issue can be related to the wrong searchable tag for entity.",
        401: "Bad Credentials.",
        403: "Something is wrong with your account, please, contact Group-IB. "
             "The issue can be related to Whitelist, Wrong API key or Wrong username.",
        404: "Not found. There is no such data on server or you are using wrong endpoint.",
        429: "Maximum count of requests per second reached, please, "
             "decrease number of requests per seconds to this collections.",
        500: "There are some troubles on server with your request.",
    }

    STATUS_CODE_FORCELIST = [429, 500, 502, 503, 504]
    RETRIES = 6
    BACKOFF_FACTOR = 1
    TIMEOUT = 120


class CollectionConsts(object):
    BASE_DATE_FORMATS = ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ"]

    COLLECTIONS_INFO = {
        # TI Collections
        "apt/threat": {"date_formats": BASE_DATE_FORMATS},
        "apt/threat_actor": {"date_formats": BASE_DATE_FORMATS},
        "attacks/ddos": {"date_formats": BASE_DATE_FORMATS},
        "attacks/deface": {"date_formats": BASE_DATE_FORMATS},
        "attacks/phishing": {"date_formats": BASE_DATE_FORMATS},
        "attacks/phishing_group": {"date_formats": BASE_DATE_FORMATS},
        "attacks/phishing_kit": {"date_formats": BASE_DATE_FORMATS},
        "compromised/account": {"date_formats": BASE_DATE_FORMATS},
        "compromised/access": {"date_formats": BASE_DATE_FORMATS},
        "compromised/account_group": {"date_formats": BASE_DATE_FORMATS},
        "compromised/bank_card_group": {"date_formats": BASE_DATE_FORMATS},
        "compromised/breached": {"date_formats": BASE_DATE_FORMATS},
        "compromised/discord": {"date_formats": BASE_DATE_FORMATS},
        "compromised/imei": {"date_formats": BASE_DATE_FORMATS},
        "compromised/masked_card": {"date_formats": BASE_DATE_FORMATS},
        "compromised/messenger": {"date_formats": BASE_DATE_FORMATS},
        "compromised/mule": {"date_formats": BASE_DATE_FORMATS},
        "compromised/reaper": {"date_formats": BASE_DATE_FORMATS},
        "hi/open_threats": {"date_formats": BASE_DATE_FORMATS},
        "hi/threat": {"date_formats": BASE_DATE_FORMATS},
        "hi/threat_actor": {"date_formats": BASE_DATE_FORMATS},
        "ioc/common": {"date_formats": BASE_DATE_FORMATS},
        "malware/cnc": {"date_formats": BASE_DATE_FORMATS},
        "malware/config": {"date_formats": BASE_DATE_FORMATS},
        "malware/malware": {"date_formats": BASE_DATE_FORMATS},
        "malware/signature": {"date_formats": BASE_DATE_FORMATS},
        "malware/yara": {"date_formats": BASE_DATE_FORMATS},
        "osi/git_repository": {"date_formats": BASE_DATE_FORMATS},
        "osi/public_leak": {"date_formats": BASE_DATE_FORMATS},
        "osi/vulnerability": {"date_formats": BASE_DATE_FORMATS},
        "suspicious_ip/open_proxy": {"date_formats": BASE_DATE_FORMATS},
        "suspicious_ip/scanner": {"date_formats": BASE_DATE_FORMATS},
        "suspicious_ip/socks_proxy": {"date_formats": BASE_DATE_FORMATS},
        "suspicious_ip/tor_node": {"date_formats": BASE_DATE_FORMATS},
        "suspicious_ip/vpn": {"date_formats": BASE_DATE_FORMATS},
    }
    DRP_COLLECTIONS_INFO = {
        # DRP Collections
        "violation/list": {"date_formats": BASE_DATE_FORMATS},
        "compromised/public_leaks": {"date_formats": BASE_DATE_FORMATS},
        "compromised/git_leaks": {"date_formats": BASE_DATE_FORMATS},
        "compromised/darkweb": {"date_formats": BASE_DATE_FORMATS},
        "compromised/breached_db": {"date_formats": BASE_DATE_FORMATS}
    }

    # TI Collections extra
    ONLY_SEARCH_COLLECTIONS = ["compromised/breached", "compromised/reaper"]
