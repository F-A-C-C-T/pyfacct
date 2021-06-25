class RequestConsts(object):
    API_URL = 'https://tap.group-ib.com/api/v2/'
    HEADERS = {"Accept": "*/*"}

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
    COLLECTIONS_INFO = {
        "compromised/account": {"date_formats": ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z"]},
        "compromised/card": {"date_formats": ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z"]},
        "compromised/breached": {"date_formats": ["%Y-%m-%d"]},
        "compromised/reaper": {"date_formats": ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z"]},
        "compromised/mule": {"date_formats": ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z"]},
        "compromised/imei": {"date_formats": ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z"]},
        "attacks/ddos": {"date_formats": ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z"]},
        "attacks/phishing": {"date_formats": ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z"]},
        "attacks/phishing_kit": {"date_formats": ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z"]},
        "attacks/deface": {"date_formats": ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z"]},
        "suspicious_ip/tor_node": {"date_formats": ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z"]},
        "suspicious_ip/open_proxy": {"date_formats": ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z"]},
        "suspicious_ip/socks_proxy": {"date_formats": ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z"]},
        "malware/targeted_malware": {"date_formats": ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z"]},
        "malware/malware": {"date_formats": ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z"]},
        "malware/cnc": {"date_formats": ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z"]},
        "osi/public_leak": {"date_formats": ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z"]},
        "osi/git_leak": {"date_formats": ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z"]},
        "osi/vulnerability": {"date_formats": ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z"]},
        "apt/threat_actor": {"date_formats": ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z"]},
        "apt/threat": {"date_formats": ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z"]},
        "bp/phishing": {"date_formats": ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z"]},
        "bp/phishing_kit": {"date_formats": ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z"]},
        "hi/threat": {"date_formats": ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z"]},
        "hi/threat_actor": {"date_formats": ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z"]}
    }

    ONLY_SEARCH_COLLECTIONS = ["compromised/breached", "compromised/reaper"]

    RECOMMENDED_IOCS_KEYS = {
        "compromised/account": ['client.ipv4.ip', 'cnc.domain', 'cnc.url', 'cnc.ipv4.ip', 'login'],
        "compromised/card": ['client.ipv4.ip', 'cnc.domain', 'cnc.url', 'cnc.ipv4.ip', 'cardInfo.number'],
        "compromised/mule": ['account', 'cnc.domain', 'cnc.url', 'cnc.ipv4.ip'],
        "compromised/imei": ['client.ipv4.ip', 'cnc.domain', 'cnc.url', 'cnc.ipv4.ip', 'device.imei'],
        "attacks/ddos": ['cnc.domain', 'cnc.url', 'cnc.ipv4.ip', 'target.ipv4.ip', 'target.url', 'target.domain'],
        "attacks/phishing": ['ipv4.ip', 'phishingDomain.domain', 'url'],
        "attacks/phishing_kit": ['emails'],
        "attacks/deface": ['target.ip', 'url'],
        "suspicious_ip/tor_node": ['ipv4.ip'],
        "suspicious_ip/open_proxy": ['ipv4.ip'],
        "suspicious_ip/socks_proxy": ['ipv4.ip'],
        "malware/targeted_malware": ['md5', 'injectMd5', 'sha1', 'sha256'],
        "malware/malware": [],
        "malware/cnc": ['domain', 'url', 'ipv4.list.ip'],
        "osi/public_leak": ['linkList.list.link'],
        "osi/git_leak": [],
        "osi/vulnerability": [],
        "apt/threat_actor": [],
        "apt/threat": [],
        "bp/phishing": ['ipv4.ip', 'phishingDomain.domain', 'url'],
        "bp/phishing_kit": ['emails'],
        "hi/threat": ['indicators.params.hashes.md5', 'indicators.params.hashes.sha1',
                      'indicators.params.hashes.sha256', 'indicators.params.url',
                      'indicators.params.domain', 'indicators.params.ipv4'],
        "hi/threat_actor": ['indicators.params.hashes.md5', 'indicators.params.hashes.sha1',
                            'indicators.params.hashes.sha256', 'indicators.params.url',
                            'indicators.params.domain', 'indicators.params.ipv4']
    }
