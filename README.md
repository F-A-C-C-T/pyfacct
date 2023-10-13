## **How to use**
1. First of all you need to initialize Poller with your credentials and set proxy (if you use it), whitelisted by GROUP-IB. Proxy must be in request-like format. Also, you can change the verification of the HTTPS certificate (False by default).
   ```python
   from cyberintegratioin import TIAPoller

   poller = TIAPoller('some@gmail.com', 'API_KEY')
   poller.set_proxies({"https": 'proxy_protocol' + "://" + 'proxy_user' + ":" + 'proxy_password' + "@" +  'proxy_ip' + ":" + 'proxy_port'})
   poller.set_verify(True)
   ```
	
2. Then you can set what data you need. Set key with the python dict in the following format: {**key_name_you_want_in_result_dict**: **data_you_want_to_find**}. Parser finds keys recursively in lists/dicts so set **data_you_want_to_find** using dot notation: **firstkey.secondkey**. If you want to add your own data to the results start your data_you_want_to_find with *. For set_keys you also can make a full template to nest data in the way you want.
	```python
	poller.set_keys("apt/threat", {'network': {'ips': 'indicators.params.ip'}, 'url': 'indicators.params.url', 'type': '*network'})
	poller.set_iocs_keys("apt/threat", {"ips": "indicators.params.ip"})
	```

3. You can use one of this functions: **create_update_generator**, **create_search_generator** - to create a generator, that returns you portions with limited feeds in it. Update generator goes through the feed in ascending order, search generator goes in descending, excluding compromised/breached and compromised/reaper collections. Most important thing: with update generator, you can set seqUpdate.
	```
	generator = poller.create_update_generator(collection_name='compromised/account', date_from='2021-01-30', date_to='2021-02-03', query='8.8.8.8', sequpdate=20000000, limit=200)
	```

4. Each portion will be presented in object of **Parser** class. You can get raw data in json format or python dictionary format. For the update generator, you can get the last feed *sequpdate* to save it locally, *count* shows you the number of feeds that still in the queue. For search generator *count* will return total number of feeds in the queue. *Parse_portion* and *get_iocs* methods use your keys and iocs_keys to return transformed data like on the example below, also you can override keys using *keys* parameter in this functions. Also you can use *bulk_parse_portion* function to get multiple parsed dicts from every feed.
	```
	for portion in generator:  
	    parsed_json = portion.parse_portion(as_json=False)  
	    iocs = portion.get_iocs(as_json=False) 
	    sequpdate = portion.sequpdate  
	    count = portion.count  
	    raw_json = portion.raw_json  
	    raw_dict = portion.raw_dict
	    new_parsed_json = portion.bulk_parse_portion(keys_list=[{"ips": "indicators.params.ip"}, {"url": 'indicators.params.url'}], as_json=False)  
	```
	For example, if you use keys and Iocs_keys from point 2 for list of feeds:  
	```python
	raw_dict = [
        {
            'indicators': {
                'params':
                    [{'ip': [1, 2], 'url': 'url.com'}, {'ip': [3], 'url': ''}]
            }
        },

        {
            'indicators': {
                'params':
                    [{'ip': [4, 5], 'url': 'new_url.com'}]
            }
        }
    ]
	```
	For parse_portion you will receive:
	```python
	parsed_json = [
          {'network': {'ips': [[1, 2], [3]]}, 'url': ['url.com', ''], 'type': 'network'},

          {'network': {'ips': [[4, 5]]}, 'url': ['new_url.com'], 'type': 'network'}
    ]
	```
	For get_iocs you will receive:
	```python
	iocs = {'ips': [1, 2, 3, 4, 5], 'url': ['url.com', 'new_url.com']}
	```
	For bulk_parse_portion you will receive:
	```python
	parsed_json = [
	    [
	        {'ips': [[1, 2], [3]]}, 
	        {'url': ['url.com', '']}
	    ],
	    [
	        {'ips': [[4, 5]]}, 
	        {'url': ['new_url.com']}
	    ]
    ]
	```
5. You can find specific feed by **id** with this command that also returns **Parser** object. Or you can get binary file from threat reports.
	```python
	feed = poller.search_feed_by_id(collection_name='compromised/account', feed_id='some_id')  
	parsed_feed = feed.parse_portion()  
	binary_file = poller.search_file_in_threats(collection_name='hi/threat', feed_id='some_id', file_id='some_file_id_inside_feed')
	```

6. Don’t forget to close session in **try…except…finally** block, or use poller with context manager.
   ```python
   from cyberintegratioin import TIAPoller
   from cyberintegratioin.exception import InputException
   
   ...
   
   try:
       poller = TIAPoller('some@gmail.com', 'API_KEY')
       ...
   except InputException as e:
       log.info("Wrong input: {0}".format(e))
   finally:
       poller.close_session()
   with TIAPoller('some@gmail.com', 'API_KEY') as poller:
       pass
   ```

7. Also you can use some additional functions if you need. You should use get_available_collections because in API response you can get collections that you have no access to.
	```python
	collection_list = poller.get_available_collections()  
	seq_update_dict = poller.get_seq_update_dict(date='2020-12-12')  
	compromised_account_sequpdate = seq_update_dict.get('compromised/account')
	```

8. Additional information about API you can find in the TI web interface or in TI Integration Guide.

9. Full version of program:
   ```python
   import logging
   from cyberintegratioin import TIAPoller
   from cyberintegratioin.exception import InputException, ConnectionException, ParserException
   
   logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
   ...
   
   try:
       poller = TIAPoller(username=username, api_key=api_key)
       poller.set_proxies({"https": proxy_protocol + "://" + proxy_user + ":" + proxy_password + "@" +  proxy_ip + ":" + proxy_port})
       poller.set_verify(True)
       for collection, keys in keys_config.items():
       poller.set_keys(collection, keys)	
       for collection, state in update_generator_config.items():
           if state.get("sequpdate"):
           generator = poller.create_update_generator(collection_name=collection, sequpdate=state.get("sequpdate"))
       elif state.get("date_from"):
           generator = poller.create_update_generator(collection_name=collection, date_from=state.get("date_from"))
       else:
           continue
       for portion in generator:
           parsed_portion = portion.parse_portion()
               save_portion(parsed_portion)
           update_generator_config[collection]["sequpdate"] = portion.sequpdate
           
   except InputException as e:
       logging.exception("Wrong input: {0}".format(e))
   except ConnectionException as e:
       logging.exception("Something wrong with connection: {0}".format(e))
   except ParserException as e:
       logging.exception("Exception occured during parsing: {0}".format(e))
   finally:
       poller.close_session()
   ```
 	In this case save_portion is example where you put your function to save data from TI.
	
	update_generator_config[collection]["sequpdate"] it is file were you should save seqUpdate for /updated API.



10. Utils

	1. Using Graph API for WHOIS information

	There are two types of searching:

	Domain:
	```python
	from cyberintegratioin import TIAPoller
	poller = TIAPoller('some@gmail.com', 'API_KEY')
	poller.set_verify(True)
	print(poller.graph_domain_search('example.com'))
	```
 	Example of the response:
	```python
	{
    "createdAt": "2015-12-10T20:40:01+00:00",
    "id": "google.com",
    "isSld": true,
    "name": "google.com",
    "sld": null,
    "updatedAt": "2023-01-12T07:30:03+00:00",
    "whois": [
        {
            "checked_at": "2023-01-12 07:51:03",
            "level": 1,
            "parsed": [
                {
                    "field": "DomainName",
                    "value": [
                        "google.com"
                    ]
                },
                {
                    "field": "Status",
                    "value": [
                        "clientdeleteprohibited https://icann.org/epp#clientdeleteprohibited",
                        "clienttransferprohibited https://icann.org/epp#clienttransferprohibited",
                        "clientupdateprohibited https://icann.org/epp#clientupdateprohibited",
                        "serverdeleteprohibited https://icann.org/epp#serverdeleteprohibited",
                        "servertransferprohibited https://icann.org/epp#servertransferprohibited",
                        "serverupdateprohibited https://icann.org/epp#serverupdateprohibited"
                    ]
                },
                {
                    "field": "Registrar",
                    "value": [
                        "markmonitor inc"
                    ]
                },
                {
                    "field": "CreationDate",
                    "value": [
                        "1997-09-15 04:00:00"
                    ]
                },
                {
                    "field": "ExpirationDate",
                    "value": [
                        "2028-09-14 04:00:00"
                    ]
                },
                {
                    "field": "UpdatedDate",
                    "value": [
                        "2019-09-09 15:39:04"
                    ]
                },
                {
                    "field": "Phone",
                    "value": [
                        "12086851750"
                    ]
                },
                {
                    "field": "NameServers",
                    "value": [
                        "ns1.google.com",
                        "ns2.google.com",
                        "ns3.google.com",
                        "ns4.google.com"
                    ]
                },
                {
                    "field": "WhoisServer",
                    "value": [
                        "whois.markmonitor.com"
                    ]
                }
            ],
            "response": "Domain Name: GOOGLE.COM\r\n   Registry Domain ID: 2138514_DOMAIN_COM-VRSN\r\n   Registrar WHOIS Server: whois.markmonitor.com\r\n   Registrar URL: http://www.markmonitor.com\r\n   Updated Date: 2019-09-09T15:39:04Z\r\n   Creation Date: 1997-09-15T04:00:00Z\r\n   Registry Expiry Date: 2028-09-14T04:00:00Z\r\n   Registrar: MarkMonitor Inc.\r\n   Registrar IANA ID: 292\r\n   Registrar Abuse Contact Email: abusecomplaints@markmonitor.com\r\n   Registrar Abuse Contact Phone: +1.2086851750\r\n   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\r\n   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\r\n   Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited\r\n   Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited\r\n   Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited\r\n   Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited\r\n   Name Server: NS1.GOOGLE.COM\r\n   Name Server: NS2.GOOGLE.COM\r\n   Name Server: NS3.GOOGLE.COM\r\n   Name Server: NS4.GOOGLE.COM\r\n   DNSSEC: unsigned\r\n   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/",
            "server": "whois.crsnic.net"
        }]
	}
	```

	IP's:
	```python
	from cyberintegratioin import TIAPoller
	poller = TIAPoller('some@gmail.com', 'API_KEY')
	poller.set_verify(True)
	print(poller.graph_ip_search('8.8.8.8'))
	```
 
 	Example of the response:
	```python
	{
    "createdAt": null,
    "created_at": null,
    "end": "8.8.8.255",
    "id": "8.8.8.0_8.8.8.255",
    "provider": "arin",
    "start": "8.8.8.0",
    "updatedAt": null,
    "updated_at": null,
    "whoisSummary": {
        "asn": "AS15169",
        "country": "US",
        "descr": "Google",
        "isp": "Google",
        "netname": "LVLT-GOGL-8-8-8",
        "person": null,
        "phone": "+1-650-253-0000"
 	    }
	}
 	```
	2. Global search

	Global search across all collections with provided `query`, returns dict with information about collection, count, etc.
	```python
	from cyberintegratioin import TIAPoller
	poller = TIAPoller('some@gmail.com', 'API_KEY')
	poller.set_verify(True)
	print(poller.global_search('8.8.8.8'))
    ```
 	Example of the response:
	```python
	[
    {
        "apiPath": "compromised/account",
        "count": 3391,
        "detailedLinks": [],
        "label": "Compromise & leaks :: Accounts",
        "link": null,
        "time": 0.0
    },
    {
        "apiPath": "attacks/deface",
        "count": 2,
        "detailedLinks": [],
        "label": "Attack :: Deface",
        "link": "https://tap.group-ib.com/attacks/deface?searchValue=8.8.8.8&q=8.8.8.8",
        "time": 0.0
    },
    {
        "apiPath": "attacks/phishing",
        "count": 1781,
        "detailedLinks": [],
        "label": "Attack :: Phishing",
        "link": "https://tap.group-ib.com/attacks/phishing?searchValue=8.8.8.8&q=8.8.8.8",
        "time": 0.0
    },
    {
        "apiPath": "hi/threat",
        "count": 1,
        "detailedLinks": [],
        "label": "Threats & Actors :: Cybercriminals :: Report",
        "link": "https://tap.group-ib.com/ta/last-threats?type=hi?searchValue=8.8.8.8&q=8.8.8.8",
        "time": 0.0
    },
    {
        "apiPath": "apt/threat",
        "count": 12,
        "detailedLinks": [],
        "label": "Threats & Actors :: Nation-State :: Report",
        "link": "https://tap.group-ib.com/ta/last-threats?type=apt?searchValue=8.8.8.8&q=8.8.8.8",
        "time": 0.0
    },
    {
        "apiPath": "apt/threat_actor",
        "count": 4,
        "detailedLinks": [],
        "label": "Threats & Actors :: Nation-State",
        "link": "https://tap.group-ib.com/common/threat_actor?searchValue=8.8.8.8&q=8.8.8.8",
        "time": 0.0
    },
    {
        "apiPath": "osi/vulnerability",
        "count": 10,
        "detailedLinks": [],
        "label": "Malware :: Vulnerabilities",
        "link": "https://tap.group-ib.com/osi/vulnerabilities?searchValue=8.8.8.8&q=8.8.8.8",
        "time": 0.0
    },
    {
        "apiPath": "osi/public_leak",
        "count": 9227,
        "detailedLinks": [],
        "label": "Compromise & leaks :: Public Leaks",
        "link": "https://tap.group-ib.com/osi/public_leak?searchValue=8.8.8.8&q=8.8.8.8",
        "time": 0.0
    },
    {
        "apiPath": "malware/polygon_task",
        "count": 3167,
        "detailedLinks": [],
        "label": "Malware :: Malware Detonation",
        "link": null,
        "time": 0.0
    }]	
	```