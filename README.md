
﻿
## **How to use**
1. First of all you need to initialize Poller with your credentials and set proxy (if you use it), whitelisted by GROUP-IB. Proxy must be in request-like format. Also, you can change the verification of the HTTPS certificate (False by default).
	```python
	from pytia import TIAPoller

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

4. Each portion will be presented in object of **Parser** class. You can get raw data in json format or python dictionary format. For the update generator, you can get the last feed *sequpdate* to save it locally, *count* shows you the number of feeds that still in the queue. For search generator *count* will return total number of feeds in the queue. *Parse_portion* and *get_iocs* methods use your keys and iocs_keys to return transformed data like on the example below. Also you can reset keys using *set_keys* and *set_iocs_keys* for current **Parser** object. It is similar to point 2 but requires only keys.
	```
	for portion in generator:  
	    parsed_json = portion.parse_portion(as_json=False)  
	    iocs = portion.get_iocs(as_json=False) 
	    sequpdate = portion.sequpdate  
	    count = portion.count  
	    raw_json = portion.raw_json  
	    raw_dict = portion.raw_dict
	    portion.set_keys({"ips": "indicators.params.ip"})
	    new_parsed_json = portion.parse_portion(as_json=False)  
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
5. You can find specific feed by **id** with this command that also returns **Parser** object. Or you can get binary file from threat reports.
	```python
	feed = poller.search_feed_by_id(collection_name='compromised/account', feed_id='some_id')  
	parsed_feed = feed.parse_portion()  
	binary_file = poller.search_file_in_threats(collection_name='hi/threat', feed_id='some_id', file_id='some_file_id_inside_feed')
	```

6. Don’t forget to close session in **try…except…finally** block, or use poller with context manager. 
	```python
	from pytia import TIAPoller
	from pytia.exception import InputException
	
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

8. Additional information about API you can find in the TI&A web interface or in TI&A Integration Guide.

9. Full version of program:
	```python
	import logging
	from pytia import TIAPoller
	from pytia.exception import InputException, ConnectionException, ParserException
	
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
