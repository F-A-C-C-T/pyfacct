# Pyfacct


[![Python](https://img.shields.io/badge/python-v3.6.8+-blue?logo=python)](https://python.org/downloads/release/python-368/)

**Pyfacct** - Python library to communicate with **Company Products** (TI, DRP) via  **API**.

## **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


## **Content**

* [Content](#content)
* [Installation](#installation)
* [Usage](#usage)
  * [Initialization](#initialization)
  * [Collections mapping](#collections-mapping)
  * [Portions generator](#portions-generator)
  * [Extra methods](#extra-methods)
    * [Available collections](#available-collections)
    * [Find feed by ID](#find-feed-by-id)
    * [Download file](#download-file)
  * [Close session](#close-session)
* [Parsing](#parsing)
  * [Parse portion method](#parse-portion-method)
  * [Get IoCs method](#get-iocs-method)
* [Examples](#examples)
  * [Full version of program](#full-version-of-program)
* [Sequence update logic](#sequence-update-logic)
  * [Sequence update](#sequence-update)
  * [API response](#api-response)
  * [Iteration steps](#iteration-steps)
  * [Stop the iteration](#stop-the-iteration)
* [Search logic](#search-logic)
* [Records limits](#records-limits)
* [Adapter](#adapter)
  * [Define Config class](#define-config-class)
  * [Create config files](#create-config-files)
  * [Create generator](#create-generator)
  * [Pack the package](#pack-the-package)
* [Troubleshooting](#troubleshooting)
  * [401 response code](#401-response-code)
  * [504 response code or timeout](#504-response-code-or-timeout)
* [FAQ](#faq)


<br>


## **Installation**

Lib deps: **pyaml**, **requests**, **urllib3**, **dataclasses**.

pyfacct lib is available on PyPI:

```
pip install pyfacct
```

Or use a Portal WHL archive. Replace `X.X.X` with current lib version:

```
pip install ./pyfacct-X.X.X-py3-none-any.whl
```



<br>



## **Usage**


### Initialization

Initialize **poller** with your credentials and set proxy (proxy should be in request-like format) if required.

Change SSL Verification using `set_verify()` method. \
If verify is set to `False`, requests will accept any TLS certificate. \
If verify is set to `True`, requiring requests to verify the TLS certificate at the remote end. \
Put a path-like string to the custom TLS certificate if required.

```python
from pyfacct import TIPoller, DRPPoller

poller = TIPoller(username='example@gmail.com', api_key='API_KEY', api_url="API_URL")
poller.set_proxies(
    proxy_protocol=PROXY_PROTOCOL,
    proxy_port=PROXY_PORT,
    proxy_ip=PROXY_ADDRESS,
    proxy_password=PROXY_PASSWORD,
    proxy_username=PROXY_USERNAME
)
poller.set_verify(True)
```

### Collections mapping

Method `set_keys()` sets **keys** to search in the selected **collection**. It should be python dict `mapping_keys = {key: value}` where \
**key** - result name \
**value** - dot-notation string with searchable keys

```python
mapping_keys = {"result_name": "searchable_key_1.searchable_key_2"}
```

Parser finds keys recursively in the API response, using dot-notation in **value**. 
If you want to add your own data to the results start the **value** with star `*`.

```python
mapping_keys = {
	"network": "indicators.params.ip", 
	"result_name": "*My_Value"
}
```

For `set_keys()` or `set_iocs_keys()` methods you can make a full template to get nested data in the way you want.

```python
mapping_keys = {
	'network': {
		'ips': 'indicators.params.ip'
	}, 
	'url': 'indicators.params.url', 
	'type': '*network'
}
poller.set_keys(collection_name="apt/threat", keys=mapping_keys)
poller.set_iocs_keys(collection_name="apt/threat", keys={"ips": "indicators.params.ip"})
```

### Portions generator

Use the next methods `create_update_generator()`, `create_search_generator()` to create a generator, which return portions of limited feeds. \
**Update generator** - goes through the feeds in ascending order. Feeds iteration based on `seqUpdate` field. \
**Search generator** - goes through the feeds in descending order. Feeds iteration based on `resultId` field.

**Note:** Update generator iterates over all collections excluding `compromised/breached` and `compromised/reaper`.
[Sequence update logic](#sequence-update-logic) is not applied to these collections.

```python
generator = poller.create_update_generator(
    collection_name='compromised/account_group', 
    date_from='2021-01-30', 
    date_to='2021-02-03', 
    query='8.8.8.8', 
    sequpdate=20000000, 
    limit=200
)
```

Each portion (iterable object) presented as `Parser` class object. 
You can get **raw data** (in json format) or **parsed portion** (python dictionary format), 
using its methods and attributes. 

```python
for portion in generator:  
    parsed_json = portion.parse_portion(as_json=False)  
    iocs = portion.get_iocs(as_json=False) 
    sequpdate = portion.sequpdate  
    count = portion.count  
    raw_json = portion.raw_json  
    raw_dict = portion.raw_dict
    new_parsed_json = portion.bulk_parse_portion(keys_list=[{"ips": "indicators.params.ip"}, {"url": 'indicators.params.url'}], as_json=False)  
```

Attribute `sequpdate` of the generator iterable object, gives you the last **sequence update number** (`seqUpdate`) 
of the feed, which you can save locally. 

```python
sequpdate = portion.sequpdate
```

Attribute `count` of the generator iterable object, shows you the number of feeds left. This amount still in the queue. 
For Search generator `count` will return total number of feeds in the queue. 

```python
count = portion.count
```

Methods `parse_portion()` and `get_iocs()` of generator iterable objects, use your 
mapping keys (IoCs keys) to return parsed data.
You can override mapping keys using `keys` parameter in these functions. 

```python
parsed_json = portion.parse_portion(as_json=False)  
iocs = portion.get_iocs(as_json=False, keys=mapping_override_keys) 
```

Also, you can use `bulk_parse_portion()` method to get multiple parsed dicts from every feed.

```python
new_parsed_json = portion.bulk_parse_portion(keys_list=[{"ips": "indicators.params.ip"}, {"url": 'indicators.params.url'}], as_json=False)
```

### Extra methods

You can use some additional functions if required. 

#### Available collections

You should use `get_available_collections()` method before the normal API response if you want to avoid 
errors trying to access collections that you have no access to.

```python
collection_list = poller.get_available_collections()  
seq_update_dict = poller.get_seq_update_dict(date='2020-12-12')  
compromised_account_sequpdate = seq_update_dict.get('compromised/account')
```

#### Find feed by ID

You can find specific feed by **id** with this command that also returns **Parser** object. 

```python
feed = poller.search_feed_by_id(collection_name='compromised/account', feed_id='some_id')  
parsed_feed = feed.parse_portion()
```

#### Download file

You can get binary file from threat reports.

```python
binary_file = poller.search_file_in_threats(collection_name='hi/threat', feed_id='some_id', file_id='some_file_id_inside_feed')
```

### Close session

Don’t forget to close session in **try…except…finally** block, or use poller with context manager.

```python
from pyfacct import TIPoller
from pyfacct.exception import InputException

...

try:
    poller = TIPoller(username='example@gmail.com', api_key='API_KEY', api_url="API_URL")
...
except InputException as e:
logger.info("Wrong input: {0}".format(e))
finally:
poller.close_session()
```



<br>



## Parsing 


Common example of API response from Collection (received feeds):

```python
api_response = [
    {
        'iocs': {
            'network': [
                {
                    'ip': [1, 2],
                    'url': 'url.com'
                },
                {
                    'ip': [3],
                    'url': ''
                }
            ]
        }
    },
    {
        'iocs': {
            'network': [
                {
                    'ip': [4, 5],
                    'url': 'new_url.com'
                }
            ]
        }
    }
]
```

### Parse portion method

Your mapping dict for `parse_portion()` or `bulk_parse_portion()` methods:

```python
mapping_keys = {
    'network': {'ips': 'iocs.network.ip'},
    'url': 'iocs.network.url',
    'type': '*custom_network'
}
```

Result of `parse_portion()` output:

```python
parsing_result = [
    {
        'network': {'ips': [[1, 2], [3]]},
        'url': ['url.com', ''],
        'type': 'custom_network'
    },
    {
        'network': {'ips': [[4, 5]]},
        'url': ['new_url.com'],
        'type': 'custom_network'
    }
]
```

Result of `bulk_parse_portion()` output:

```python
parsing_result = [
    [
        {
            'network': {'ips': [[1, 2], [3]]}, 
            'url': ['url.com', ''], 
            'type': 'custom_network'}
    ],
    [
        {
            'network': {'ips': [[4, 5]]},
            'url': ['new_url.com'], 
            'type': 'custom_network'}
    ]
]
```

### Get IoCs method

Your mapping dict for `get_iocs()` method:

```python
mapping_keys = {
    'ips': 'iocs.network.ip',
    'url': 'iocs.network.url'
}
```

Result of `get_iocs()` output:

```python
parsing_result = {
    'ips': [1, 2, 3, 4, 5], 
    'url': ['url.com', 'new_url.com']
}
```


<br>



## Examples

### Full version of program

```python
import logging
from pyfacct import TIPoller
from pyfacct.exception import InputException, ConnectionException, ParserException

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
...

try:
    poller = TIPoller(username=username, api_key=api_key, api_url=api_url)
    poller.set_proxies(proxy_protocol=PROXY_PROTOCOL,
                       proxy_port=PROXY_PORT,
                       proxy_ip=PROXY_ADDRESS,
                       proxy_password=PROXY_PASSWORD,
                       proxy_username=PROXY_USERNAME)
    poller.set_verify(True)
    for collection, keys in keys_config.items():
        poller.set_keys(collection, keys)
    for collection, state in update_generator_config.items():
        if state.get("sequpdate"):
            generator = poller.create_update_generator(collection_name=collection, sequpdate=state.get("sequpdate"))
    elif state.get("date_from"):
    sequpdate = poller.get_seq_update_dict(date=state.get('date_from'), collection_name=collection).get(collection)
    generator = poller.create_update_generator(collection_name=collection, sequpdate=sequpdate)
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


<br>



## API logic

To iterate over received portions from API response, you should follow one of the next iteration logic: 

- **Result ID iteration** - based on `resultId` parameter, which was retrieved from previous response.
Uses common collection name endpoint (`apt/threat`) which is added to the base URL >>> `/api/v2/apt/threat`. 
- **Sequence update iteration** - based on `seqUpdate` parameter, which was retrieved from previous response.
Uses updated endpoint (`/updated`) after collection name (`/apt/threat`) >>> `/api/v2/apt/threat/updated`.

To search IPs, domains, hashes, emails, etc., you should follow the next logic: 

- **Search logic** - 
First you should reach `/api/v2/search` endpoint with any `q` parameter >>> `/api/v2/search?q=8.8.8.8`.
In the output response you will receive collections, which contains the search result (`8.8.8.8`).
Use _Sequence update iteration_ as a next step to retrieve all events.


To get the latest updates on each collection events you should follow the next logic: 

- **Sequence update logic** - 
first you should reach `/api/v2/sequnce_list` endpoint with `date` and `collection` parameters (optional) >>> `/api/v2/search?date=2022-01-01&collection=apt/threat`.
In the output response you will receive `seqUpdate` number, which you should use in the next request to collection `/updated` endpoint.
Use _Sequence update iteration_ as a next step to retrieve all events.

<br>



### Sequence update logic

Most of the collections at the Threat Intelligence portal has `/updated` endpoint. 
And this endpoint uses updated logic based on `seqUpdate` key field, which comes from API JSON response.

The `seqUpdate` key – is a time from Epoch converted to a big number (microseconds), using the next formula:

```text
UTC timestamp * 1000 * 1000. 
```

_Note:_ Don't rely on this formula. Because of the rising amount of data it could be changed. 
For that purpose `/api/v2/sequence_list` endpoint was created. 
Use this endpoint to get required `seqUpdate` number.

#### API response

Each row in our database has its own unique sequence update number. So, we can get all the events one by one. 
To check it you can explore JSON output and then explore each item in the `"items"` field. 
So, each item contains a `seqUpdate` field. And the last element’s `seqUpdate` is put to the top level of JSON output. 
You can use it to get the next portion of feeds. 
Each collection has its own updated route like `/api/v2/apt/threat/updated`, so we can use the next output as an example.

```json
{
    "count": 1761,
    "items": [
        {"id": "fake286ca753feed3476649438e4e4488"...},
        {"id": "fake51d29357b22b80564a1d2f9fc8751"...},
        {
            "author": null,
            "companyId": [],
            "id": "fake4f16300296d20ef9b909dc0d354fb",
            ......,
            "indicators": [
                {
                    "dateFirstSeen": null,
                    "dateLastSeen": null,
                    "deleted": false,
                    "description": null,
                    "domain": "fake-fakesop.net",
                    "id": "fakebe483bb82759fbee7038235e0f52d0",
                    .....
                }
            ],
            "indicatorsIds": [
                "fakebe483bb82759fbee7038235e0f52d0"
            ],
            "isPublished": true,
            "isTailored": false,
            "labels": [],
            "langs": [
                "en"
            ],
            "malwareList": [],
            ......,
            "seqUpdate": 16172928022293
        },
    ],
    "seqUpdate": 16172928022293
}
```

#### Iteration steps

To iterate over `/api/v2/apt/threat/updated` endpoint data, you need to collect this 
field number (`"seqUpdate": 16172928022293`) right at the top level of the JSON response, 
received from previous request or from `/sequnce_list` endpoint.

```console
curl -X 'GET' 'https://<base URL>/api/v2/sequnce_list'
```

Add gathered `seqUpdate` in the next request, using endpoint params.

```console
curl -X 'GET' 'https://<base URL>/api/v2/apt/threat/updated?seqUpdate=16172928022293'
```

In the received JSON output check the `"count": 1751`. -> \
Gather `seqUpdate` from last feed or at top level -> \
Put it in next request -> 

```console
curl -X 'GET' 'https://<base URL>/api/v2/apt/threat/updated?seqUpdate=16172928536227'
```

In the received JSON output, check the `"count": 1741` -> \
Gather `seqUpdate` from last feed or at top level -> \
Repeat till the end.

#### Stop the iteration

The "stop word" in that logic is items `"count"` or `"items"` list length. 
For the collection `apt/threat` in above example, the `limit` is set to 10 by default, 
the other collections usually have 100 `limit`. The limit depends on the amount of data to not overload the JSON output.
For example, usually you receive a portion of 100 feeds (not 10) for the first iteration. -> 
Then could be a portion of 23 feeds -> Then a portion of 0 feeds -> The end.

<br>



### Search logic

Search logic is used to find attribution to the search value in Threat Intelligence database.

#### Global search

To find events related to IP, domain, hash, email, etc., you should send request to the `/api/v2/search` endpoint 
with any `q` parameter (`/api/v2/search?q=8.8.8.8`). 
It will return a list of collections, which contains this searchable parameter. 
As a next step we need to use _Sequence update iteration_ over all items in each collection.
You can specify the searchable type keyword to avoid side results by setting `q` parameter like `/api/v2/search?q=ip:8.8.8.8`.
The same can be done for domain, email, hash, etc (`/api/v2/search?q=domain:google.com`, `/api/v2/search?q=email:example@gmail.com`).


```json
[
    {
        "apiPath": "suspicious_ip/open_proxy",
        "label": "Suspicious IP :: Open Proxy",
        "link": "https://<base-url>/api/v2/suspicious_ip/open_proxy?q=ip:8.8.8.8",
        "count": 14,
        "time": 0.304644684,
        "detailedLinks": null
    },
    {
        "apiPath": "attacks/ddos",
        "label": "Attack :: DDoS",
        "link": "https://<base-url>/api/v2/attacks/ddos?q=ip:8.8.8.8",
        "count": 1490,
        "time": 0.389418291,
        "detailedLinks": null
    },
    {"apiPath": "attacks/deface"...},
    {"apiPath": "malware/config"...},
    {"apiPath": "suspicious_ip/scanner"...}
]

```


#### Iteration steps

On the first search step we receive information that collection `attacks/ddos` contains 1490 items (`"count": 1490`). 
Let's extract all of them. First we need to send request to this collection with the `q` parameter (`?q=ip:8.8.8.8`).
Then we retrieve `"seqUpdate"` field right at the top level of the JSON response and use it in the next request (`"seqUpdate": 1673373011294`).

```json
{
  "count": 1490,
  "items": [
    {
      "body": null,
      "cnc": {"cnc": "http://ex-ex.net/drv/"...},
      "company": null,
      "companyId": null,
      "dateBegin": null,
      "dateEnd": null,
      "dateReg": "2017-08-16T00:00:00+00:00",
      "evaluation": {},
      "favouriteForCompanies": [],
      "headers": [],
      "hideForCompanies": [],
      "id": "examplec58903baddc84b8c51eaef1f904374025d",
      "isFavourite": false,
      ...
    }
  ],
  ...,
  "seqUpdate": 1673373011294
}
```

So the next request should look like this `/api/v2/attacks/ddos/updated?q=ip:8.8.8.8&seqUpdate=1673373011294`.
We can also set the `limit` parameter in the requests, like `limit=500`.
Explore the example below.

```console
curl -X 'GET' 'https://<base URL>/api/v2/search?q=ip:8.8.8.8'
```

Add gathered `seqUpdate` in the next request, using endpoint params.

```console
curl -X 'GET' 'https://<base URL>/api/v2/apt/threat/updated?seqUpdate=1673373011294'
```

In the received JSON output check the `"count": 1390`. -> \
Gather `seqUpdate` from last feed or at top level -> \
Put it in next request -> 

```console
curl -X 'GET' 'https://<base URL>/api/v2/apt/threat/updated?seqUpdate=1673375930599'
```

In the received JSON output, check the `"count": 1290` -> \
Gather `seqUpdate` from last feed or at top level -> \
Repeat till the end.

#### Stop the iteration

The "stop word" in that logic is items `"count"` or `"items"` list length. 
For the collection `attacks/ddos` in above example, the `limit` is set to 100 by default, 
the other collections it may differ. The limit depends on the amount of data to not overload the JSON output.
For example, usually you receive a portion of 100 feeds for the first iteration. -> 
Then could be a portion of 23 feeds -> Then a portion of 0 feeds -> The end.



<br>



## Records limits

Default limit is 100 records per request. Due to different size of feeds there are different limits for getting data.

To change record limit in response add param `limit=500` to the request. 
All limits for different collections can be found at Portal documentation.

```console
curl -X 'GET' 'https://<base URL>/api/v2/apt/threat/updated?limit=500&seqUpdate=16172928022293'
```

<br>


## Troubleshooting

### 401 response code

This code is return if you sent no credentials. Make sure that you send Authorization header and that you use Basic auth.

### 403 response code

There are several possible reasons of it:

- IP limitation. Make sure that you request from allowed IP address. You can find above how to set up your private IP list.
- API KEY issue. Make sure that your API KEY is active and valid. Try regeneration it as it was described above.
- No access to the feed. make sure that you have access to the requested feed. You can find available feed on Profile page -> Security and Access

### 504 response code or timeout

Try setting a smaller limit when requesting the API.


## FAQ

Have a question? Ask in the SD Ticket on our Portal or integration@facct.ru
