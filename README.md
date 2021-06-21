
## **How to use**
1. First of all you need to initialize Poller with your credentials and set proxy (if you use it), whitlisted by GROUP-IB. Proxy must be in request-like format. Also, you can change the verification of the HTTPS certificate (False by default).
	```python
	from pytia import TIAPoller

	poller = TIAPoller('some@gmail.com', 'API_KEY')
	poller.set_proxies({"https": 'proxy_protocol' + "://" + 'proxy_user' + ":" + 'proxy_password' + "@" +  'proxy_ip' + ":" + 'proxy_port'})
	poller.set_verify(True)
	```
	
2. Then you can set what data you need from feeds. Set keys in format **firstkey.secondkey** and module will find it recursively. Also you can set an alias for result dict using colon **firstkey.secondkey:result_key**.
	```python
	poller.set_keys('compromised/account', ['iocs.network.ip:ips', 'iocs.network.url'])  
	poller.set_iocs_keys('compromised/account', ['iocs.network.ip:ips', 'iocs.network.url'])
	```

3. You can use one of this functions: **create_update_generator**, **create_search_generator** - to create a generator, that returns you portions with limited feeds in it. Update generator goes through the feed in ascending order, search generator goes in descending. Most important thing: with update generator, you can set seqUpdate
	```
	generator = poller.create_update_generator(collection_name='compromised/account', date_from='2021-01-30', date_to='2021-02-03', query='8.8.8.8', seqUpdate=20000000, limit=200)
	```

4. Each portion will be presented in object of **Parser** class. You can get raw data in json format or python dictionary format. For the update generator, you can get the last feed seqUpdate to save it locally, count shows you the number of feeds that still in the queue. For search generator count will return total number of feeds in the queue. Parse_portion and get_iocs methods use you keys and iocs_keys to return transformed data like on example below.
	```
	for portion in generator:  
	    parsed_json = portion.parse_portion(as_json=False)  
	    iocs = portion.get_iocs(as_json=False) 
	    seqUpdate = portion.seqUpdate  
	    count = portion.count  
	    raw_json = portion.raw_json  
	    raw_dict = portion.raw_dict
	```
	For example, if you use keys and Iocs_keys from point 2 for list of feeds:  
	```python
	[
	    { 
	        'iocs': { 
	            'network': [
		        {'ip': [1, 2], 'url': 'url.com'}, 
			{'ip': [3], 'url': ''}
		    ] 
		} 
	    },  
	    { 
	        'iocs': { 
	            'network': [{'ip': [4, 5], 'url': 'new_url.com'}] 
		} 
	    }
	]
	```
	For parse_portion you will receive:
	```python
	[
	    {'ips': [[1, 2], [3]], 'iocs.network.url': ['url.com', '']},  
	    {'ips': [[4, 5]], 'iocs.network.url': ['new_url.com']}
	]
	```
	For get_iocs you will receive:
	```python
	{'ips': [1, 2, 3, 4, 5], 'iocs.network.url': ['url.com', 'new_url.com']}
	```
5. You can find specific feed by **id** with this command that also returns **Parser** object. Or you can get binary file from threats.
	```python
	feed = poller.search_feed_by_id(collection_name='compromised/account', feed_id='some_id')  
	parsed_feed = feed.parse_portion()  
	binary_file = poller.search_file_in_threats(collection_name='hi/threat', feed_id='some_id', file_id='some_file_id_inside_feed')
	```

6. Don’t forget to close session in **try…catch** block, or use poller with context manager. 
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

7. Also you can use some additional functions if you need. You should use get_available_collections because in API response you can get collections that you can't work with.
	```python
	collection_list = poller.get_available_collections()  
	seq_update_dict = poller.get_seq_update_dict(date='2020-12-12')  
	compromised_account_seqUpdate = seq_update_dict.get('compromised/account')
	```

