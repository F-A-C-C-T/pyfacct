API_URL = 'https://tap.group-ib.com/api/v2/'
HEADERS = {"Accept": "*/*"}

STATUS_CODE_MSGS = {
    401: "Bad Credentials",
    403: "Something is wrong with your account, please, contact GIB.",
    404: "Not found. There is no such data on server.",
    500: "There are some troubles on server with your request.",
    301: "Verify that your public IP is whitelisted by Group IB.",
    302: "Verify that your public IP is whitelisted by Group IB.",
    429: "Maximum count of requests per second reached, please, increase limits in configuration file."
}

COLLECTIONS = ["compromised/account", "compromised/card", "compromised/mule", "compromised/imei", "attacks/ddos",
               "attacks/phishing", "attacks/phishing_kit", "attacks/deface", "suspicious_ip/tor_node",
               "suspicious_ip/open_proxy", "suspicious_ip/socks_proxy", "malware/targeted_malware", "malware/malware",
               "malware/cnc", "osi/public_leak", "osi/git_leak", "osi/vulnerability", "apt/threat_actor", "apt/threat",
               "bp/phishing", "bp/phishing_kit", "hi/threat", "hi/threat_actor"]

