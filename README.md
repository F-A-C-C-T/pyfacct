
## **How to use**
1. First of all you need to initialize Poller with your credentials and set proxy (if you use it), whitlisted by GROUP-IB. Proxy must be in request-like format.
	```
	from pytia import TIAPoller

	poller = TIAPoller('some@gmail.com', 'API_KEY')  
	poller.set_proxies({"https": 'proxy_protocol' + "://" + 'proxy_user' + ":" + 'proxy_password' + "@" +  'proxy_ip' + ":" + 'proxy_port'})
	```
	
2. Then you can set, what data you need from feeds. Set keys in format **firstkey.secondkey** and module will find it recursively. For example for dict {firstkey: {secondkey: info}} you will get {firstkey.secondkey: info}. Keys for iocs is set by default, so you can leave it unchanged.
	```
	poller.set_keys('compromised/account', ['evaluation.admiraltyCode', 'sourceType'])  
	poller.set_iocs_keys('compromised/account', ['cnc.ipv4.ip'])
	```

3. You can use one of this functions: **create_update_generator**, **create_search_generator** - to create a generator, that returns you portions with limited feeds in it. While updating you will get the last version of each feed, but while searching you will find change history.
	```
	generator = poller.create_update_generator(collection_name='compromised/account', date_from='2021-01-30', date_to='2021-02-03', query='8.8.8.8', seqUpdate=20000000, limit=200)
	```

4. Each portion will be presented in object of **Parser** class.
   Iocs returns in this format: {‘cnc.ipv4.ip’: [‘2.2.2.2’, ‘8.8.8.8’, ‘10.10.10.10’].
   Parsed_json in this format: [{‘evaluation.admiraltyCode’: ‘A2’, ‘sourceType’: ‘Botnet’}, {‘evaluation.admiraltyCode’: ‘A2’, ‘sourceType’: ‘Botnet’}]
	```
	for portion in generator:  
	    parsed_json = portion.parse_portion(as_json=False)  
	    iocs = portion.get_iocs(as_json=False) 
	    seqUpdate = portion.seqUpdate  
	    count = portion.count  
	    raw_json = portion.raw_json  
	    raw_dict = portion.raw_dict
	```
5. You can find specific feed by **id** with this command that also returns **Parser** object. Or you can get binary file from threats.
	```
	feed = poller.search_feed_by_id(collection_name='compromised/account', feed_id='some_id')  
	parsed_feed = feed.parse_portion()  
	file = poller.search_file_in_threats(collection_name='hi/threat', feed_id='some_id', file_id='some_file_id_inside_feed')
	```

6. Don’t forget to close session in **try…catch** block, or use poller with context manager.
	```
	poller.close_session()
	with TIAPoller('some@gmail.com', 'API_KEY') as poller:
	    pass
	```

7. Also you can use some additional functions if you need.
	```
	collection_list = poller.get_available_collections()  
	seq_update_dict = poller.get_seq_update_dict(date='2020-12-12')  
	compromised_account_seqUpdate = seq_update_dict.get('compromised/account')
	```

