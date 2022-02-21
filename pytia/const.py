class TechnicalConsts(object):
    library_version = "0.5.5"


class RequestConsts(object):
    API_URL = 'https://tap.group-ib.com/api/v2/'
    HEADERS = {
        "Accept": "*/*",
        "User-Agent": f"pytia/{TechnicalConsts.library_version}"
    }

    STATUS_CODE_MSGS = {
        401: "Bad Credentials",
        403: "Something is wrong with your account, please, contact GIB.",
        404: "Not found. There is no such data on server.",
        500: "There are some troubles on server with your request.",
        301: "Verify that your public IP is whitelisted by Group IB.",
        302: "Verify that your public IP is whitelisted by Group IB.",
        429: "Maximum count of requests per second reached, please, "
             "decrease number of requests per seconds to this collections."
    }

    STATUS_CODE_FORCELIST = [429, 500]
    RETRIES = 4
    BACKOFF_FACTOR = 1
    TIMEOUT = 60


class CollectionConsts(object):
    BASE_DATE_FORMATS = ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ"]

    COLLECTIONS_INFO = {
        "compromised/account": {"date_formats": BASE_DATE_FORMATS},
        "compromised/card": {"date_formats": BASE_DATE_FORMATS},
        "compromised/breached": {"date_formats": BASE_DATE_FORMATS},
        "compromised/reaper": {"date_formats": BASE_DATE_FORMATS},
        "compromised/mule": {"date_formats": BASE_DATE_FORMATS},
        "compromised/imei": {"date_formats": BASE_DATE_FORMATS},
        "attacks/ddos": {"date_formats": BASE_DATE_FORMATS},
        "attacks/phishing": {"date_formats": BASE_DATE_FORMATS},
        "attacks/phishing_kit": {"date_formats": BASE_DATE_FORMATS},
        "attacks/deface": {"date_formats": BASE_DATE_FORMATS},
        "suspicious_ip/tor_node": {"date_formats": BASE_DATE_FORMATS},
        "suspicious_ip/open_proxy": {"date_formats": BASE_DATE_FORMATS},
        "suspicious_ip/socks_proxy": {"date_formats": BASE_DATE_FORMATS},
        "malware/targeted_malware": {"date_formats": BASE_DATE_FORMATS},
        "malware/malware": {"date_formats": BASE_DATE_FORMATS},
        "malware/cnc": {"date_formats": BASE_DATE_FORMATS},
        "osi/public_leak": {"date_formats": BASE_DATE_FORMATS},
        "osi/git_leak": {"date_formats": BASE_DATE_FORMATS},
        "osi/vulnerability": {"date_formats": BASE_DATE_FORMATS},
        "apt/threat_actor": {"date_formats": BASE_DATE_FORMATS},
        "apt/threat": {"date_formats": BASE_DATE_FORMATS},
        "bp/phishing": {"date_formats": BASE_DATE_FORMATS},
        "bp/phishing_kit": {"date_formats": BASE_DATE_FORMATS},
        "hi/threat": {"date_formats": BASE_DATE_FORMATS},
        "hi/threat_actor": {"date_formats": BASE_DATE_FORMATS}
    }

    ONLY_SEARCH_COLLECTIONS = ["compromised/breached", "compromised/reaper"]
