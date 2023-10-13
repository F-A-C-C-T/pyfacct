class TechnicalConsts(object):
    default = 'unknown'

    library_name = "gibunipy"
    library_version = "0.5.21"
    system_type = "Lib"
    system_name = default
    system_version = default
    product_name = "gibunipy_lib"
    product_version = "0.5.21"

class RequestConsts(object):
    API_URL = 'https://tap.group-ib.com/api/v2/'
    HEADERS = {
        "Accept": "*/*",
        "User-Agent": f"gibunipy/{TechnicalConsts.library_version}"
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

    STATUS_CODE_FORCELIST = [429, 500, 502, 503, 504]
    RETRIES = 6
    BACKOFF_FACTOR = 1
    TIMEOUT = 120


class CollectionConsts(object):
    BASE_DATE_FORMATS = ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ"]

    ### ALL collectoin which exist should be provied with collection list
    COLLECTIONS_INFO = {
        "compromised/account": {"date_formats": BASE_DATE_FORMATS},
        "compromised/account_group": {"date_formats": BASE_DATE_FORMATS},
        "compromised/card": {"date_formats": BASE_DATE_FORMATS},
        "compromised/bank_card": {"date_formats": BASE_DATE_FORMATS},
        "compromised/bank_card_group": {"date_formats": BASE_DATE_FORMATS},
        "compromised/masked_card": {"date_formats": BASE_DATE_FORMATS},
        "compromised/breached": {"date_formats": BASE_DATE_FORMATS},
        "compromised/reaper": {"date_formats": BASE_DATE_FORMATS},
        "compromised/mule": {"date_formats": BASE_DATE_FORMATS},
        "compromised/imei": {"date_formats": BASE_DATE_FORMATS},
        "compromised/access": {"date_formats": BASE_DATE_FORMATS},
        "compromised/messenger": {"date_formats": BASE_DATE_FORMATS},
        "attacks/ddos": {"date_formats": BASE_DATE_FORMATS},
        "attacks/phishing": {"date_formats": BASE_DATE_FORMATS},
        "attacks/phishing_group": {"date_formats": BASE_DATE_FORMATS},
        "attacks/phishing_kit": {"date_formats": BASE_DATE_FORMATS},
        "attacks/deface": {"date_formats": BASE_DATE_FORMATS},
        "suspicious_ip/tor_node": {"date_formats": BASE_DATE_FORMATS},
        "suspicious_ip/open_proxy": {"date_formats": BASE_DATE_FORMATS},
        "suspicious_ip/socks_proxy": {"date_formats": BASE_DATE_FORMATS},
        "suspicious_ip/scanner": {"date_formats": BASE_DATE_FORMATS},
        "suspicious_ip/vpn": {"date_formats": BASE_DATE_FORMATS},
        "malware/targeted_malware": {"date_formats": BASE_DATE_FORMATS},
        "malware/malware": {"date_formats": BASE_DATE_FORMATS},
        "malware/cnc": {"date_formats": BASE_DATE_FORMATS},
        "malware/config": {"date_formats": BASE_DATE_FORMATS},
        "malware/signature": {"date_formats": BASE_DATE_FORMATS},
        "malware/yara": {"date_formats": BASE_DATE_FORMATS},
        "osi/public_leak": {"date_formats": BASE_DATE_FORMATS},
        "osi/git_leak": {"date_formats": BASE_DATE_FORMATS},
        "osi/git_repository": {"date_formats": BASE_DATE_FORMATS},
        "osi/vulnerability": {"date_formats": BASE_DATE_FORMATS},
        "apt/threat_actor": {"date_formats": BASE_DATE_FORMATS},
        "apt/threat": {"date_formats": BASE_DATE_FORMATS},
        "bp/phishing": {"date_formats": BASE_DATE_FORMATS},
        "bp/phishing_kit": {"date_formats": BASE_DATE_FORMATS},
        "hi/threat": {"date_formats": BASE_DATE_FORMATS},
        "hi/threat_actor": {"date_formats": BASE_DATE_FORMATS},
        "ioc/common": {"date_formats": BASE_DATE_FORMATS},
        "utils/graph/domain": {"date_formats": BASE_DATE_FORMATS},
        "utils/graph/ip": {"date_formats": BASE_DATE_FORMATS}
    }

    ONLY_SEARCH_COLLECTIONS = ["compromised/breached", "compromised/reaper"]
