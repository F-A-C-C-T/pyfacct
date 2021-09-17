"""

This module contains poller for GIB TI&A.

"""

import requests
import json
import logging
from urllib.parse import urljoin, urlencode
from requests.auth import HTTPBasicAuth
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from typing import Union, Optional, List, Dict, Any, Generator
from .exception import ConnectionException, ParserException
from .const import *
from .utils import Validator, ParserHelper

pytia_logger = logging.getLogger("pytia")


class TIAPoller(object):
    """
    Poller that can be used for requests to GIB TI&A.

    :param str username: Login for GIB TI&A.
    :param str api_key: API key, generated in GIB TI&A.
    :param str api_url: (optional) URL for GIB TI&A.
    """
    def __init__(self, username: str, api_key: str, api_url: str = RequestConsts.API_URL):
        """
        :param username: Login for GIB TI&A.
        :param api_key: API key, generated in GIB TI&A.
        :param api_url: (optional) URL for GIB TI&A.
        """
        self._session = requests.Session()
        self._session.auth = HTTPBasicAuth(username, api_key)
        self._session.headers.update(RequestConsts.HEADERS)
        self._session.verify = False
        self._api_url = api_url
        self._keys = {}
        self._iocs_keys = {}
        self._mount_adapter_with_retries()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._session.close()

    def _mount_adapter_with_retries(self, retries=RequestConsts.RETRIES,
                                    backoff_factor=RequestConsts.BACKOFF_FACTOR,
                                    status_forcelist=RequestConsts.STATUS_CODE_FORCELIST):
        retry = Retry(
            total=retries,
            read=retries,
            connect=retries,
            backoff_factor=backoff_factor,
            status_forcelist=status_forcelist
        )
        adapter = HTTPAdapter(max_retries=retry)
        self._session.mount('http://', adapter)
        self._session.mount('https://', adapter)

    def _send_request(self, url, params, decode=True, **kwargs):
        params = {k: v for k, v in params.items() if v}
        params = urlencode(params)
        try:
            response = self._session.get(url, params=params, timeout=RequestConsts.TIMEOUT)
            status_code = response.status_code
            if status_code == 200:
                if decode:
                    return response.json()
                else:
                    return response.content
            elif status_code in RequestConsts.STATUS_CODE_MSGS:
                raise ConnectionException("Status code: {0}. "
                                          "Message: {1}".format(status_code,
                                                                RequestConsts.STATUS_CODE_MSGS[status_code]))
            else:
                raise ConnectionException("Something wrong. Status code: {0}. "
                                          "Response body: {1}.".format(status_code, response.text))
        except requests.exceptions.Timeout as e:
            raise ConnectionException("Max retries reached. Exception message: {0}".format(e))

    def set_proxies(self, proxies: dict):
        """
        Sets proxies for `Session` object.

        :param proxies: requests-like proxies.
        """
        self._session.proxies = proxies

    def set_verify(self, verify: bool):
        """
        Sets verify for `Session` object.

        :param verify: true for verify certificate, false for requests without verifying.
        """
        self._session.verify = verify

    def set_keys(self, collection_name: str, keys: Dict[str, str]):
        """
        Sets keys to search in the selected collection. `keys` should be python dict in this format:
        {key_name_you_want_in_result_dict: data_you_want_to_find}. Parser finds keys recursively in lists/dicts
        so set `data_you_want_to_find` using dot notation: ``firstkey.secondkey``. If you want to add your own data
        to the results start your data_you_want_to_find with *. You also can make a full template to nest data
        in the way you want.

        For example:
        Keys {'network': {'ips': 'iocs.network.ip'}, 'url': 'iocs.network.url', 'type': '*network'} for list of feeds:

        [
            {
                'iocs': {
                    'network':
                        [{'ip': [1, 2], 'url': 'url.com'}, {'ip': [3], 'url': ''}]
                }
            },

            {
                'iocs': {
                    'network':
                        [{'ip': [4, 5], 'url': 'new_url.com'}]
                }
            }
        ]

        return this

        [
            {'network': {'ips': [[1, 2], [3]]}, 'url': ['url.com', ''], 'type': 'network'},

            {'network': {'ips': [[4, 5]]}, 'url': ['new_url.com'], 'type': 'network'}
        ]

        :param collection_name: name of the collection whose keys to set.
        :param keys: python dict with keys to get from parse.
        """
        Validator.validate_collection_name(collection_name)
        Validator.validate_set_keys_input(keys)
        self._keys[collection_name] = keys

    def set_iocs_keys(self, collection_name: str, keys: Dict[str, str]):
        """
        Sets keys to search IOCs in the selected collection. `keys` should be the python dict in this format:
        {key_name_you_want_in_result_dict: data_you_want_to_find}. Parser finds keys recursively in lists/dicts
        so set `data_you_want_to_find` using dot notation: ``firstkey.secondkey``.

        For example:
        Keys {'ips': 'iocs.network.ip', 'url': 'iocs.network.url'} for list of feeds:

        [
            {
                'iocs': {
                    'network':
                        [{'ip': [1, 2], 'url': 'url.com'}, {'ip': [3], url: ""}]
                }
            },

            {
                'iocs': {
                    'network':
                        [{'ip': [4, 5], 'url': 'new_url.com'}]
                }
            }
        ]

        return this `{'ips': [1, 2, 3, 4, 5], 'url': ['url.com', 'new_url.com']}`.

        :param collection_name: name of the collection whose keys to set.
        :param keys: python dict with keys to get from parse.
        """
        Validator.validate_collection_name(collection_name)
        Validator.validate_set_iocs_keys_input(keys)
        self._iocs_keys[collection_name] = keys

    def create_update_generator(self, collection_name: str, date_from: Optional[str] = None,
                                date_to: Optional[str] = None, query: Optional[str] = None,
                                sequpdate: Union[int, str] = None, limit: Union[int, str] = 200):
        """
        Creates generator of :class:`Parser` class objects for an update session
        (feeds are sorted in ascending order) for `collection_name` with set parameters.

        `sequpdate` allows you to receive all relevant feeds. Such a request uses the sequpdate parameter,
        you will receive a portion of feeds that starts with the next `sequpdate` parameter for the current collection.
        For all feeds in the Group IB Intelligence continuous numbering is carried out.
        For example, the `sequpdate` equal to 1999998 can be in the `compromised/accounts` collection,
        and a feed with sequpdate equal to 1999999 can be in the `attacks/ddos` collection.
        If item updates (for example, if new attacks were associated with existing APT by our specialists or tor node
        has been detected as active again), the item gets a new parameter and it automatically rises in the database
        and "becomes relevant" again.

        .. warning:: Dates should be in one of this formats: "YYYY-MM-DD", "YYYY-MM-DDThh:mm:ssz".
        For most collections, limits are set on the server and can't be exceeded.

        :param collection_name: collection to update.
        :param date_from: start date of update session.
        :param date_to: end date of update session.
        :param query: query to search during update session.
        :param sequpdate: identification number from which to start the session.
        :param limit: size of portion in iteration.
        :rtype: Generator[:class:`Parser`]
        """
        Validator.validate_collection_name(collection_name, method="update")
        if date_from:
            Validator.validate_date_format(
                date=date_from,
                formats=CollectionConsts.COLLECTIONS_INFO.get(collection_name).get("date_formats")
            )
        if date_to:
            Validator.validate_date_format(
                date=date_to,
                formats=CollectionConsts.COLLECTIONS_INFO.get(collection_name).get("date_formats")
            )
        pytia_logger.info('Starting update session for {0} collection'.format(collection_name))
        limit = int(limit)
        url = urljoin(self._api_url, collection_name + '/updated')
        i = 0
        total_amount = 0
        while True:
            i += 1
            pytia_logger.info('Loading {0} portion, starting from sequpdate={1}'.format(i, sequpdate))
            chunk = self._send_request(url=url, params={'df': date_from, 'dt': date_to, 'q': query,
                                                        'limit': limit, 'seqUpdate': sequpdate})
            portion = Parser(chunk, self._keys.get(collection_name, []),
                             self._iocs_keys.get(collection_name, []))
            sequpdate = portion.sequpdate
            date_from = None
            pytia_logger.info('{0} portion was loaded'.format(i))
            if portion.portion_size == 0:
                pytia_logger.info('Update session for {0} collection was finished, '
                                  'loaded {1} feeds'.format(collection_name, total_amount))
                break
            total_amount += portion.portion_size
            yield portion

    def create_search_generator(self, collection_name: str, date_from: str = None, date_to: Optional[str] = None,
                                query: Optional[str] = None, limit: Union[str, int] = 200):
        """
        Creates generator of :class:`Parser` class objects for the search session 
        (feeds are sorted in descending order, **excluding compromised/breached amd compromised/reaper**)
        for `collection_name` with set parameters.

        .. warning:: Dates should be in one of this formats: "YYYY-MM-DD", "YYYY-MM-DDThh:mm:ssz".
        For most collections, limits are set on the server and can't be exceeded.

        :param collection_name: collection to search.
        :param date_from: start date of search session.
        :param date_to: end date of search session.
        :param query: query to search during session.
        :param limit: size of portion in iteration.
        :rtype: Generator[:class:`Parser`]
        """
        Validator.validate_collection_name(collection_name, method="search")
        if date_from:
            Validator.validate_date_format(
                date=date_from,
                formats=CollectionConsts.COLLECTIONS_INFO.get(collection_name).get("date_formats")
            )
        if date_to:
            Validator.validate_date_format(
                date=date_to,
                formats=CollectionConsts.COLLECTIONS_INFO.get(collection_name).get("date_formats")
            )
        pytia_logger.info('Starting search session for {0} collection'.format(collection_name))
        limit = int(limit)
        result_id = None
        url = urljoin(self._api_url, collection_name)
        i = 0
        total_amount = 0
        while True:
            i += 1
            pytia_logger.info('Loading {0} portion'.format(i))
            chunk = self._send_request(url=url, params={'df': date_from, 'dt': date_to, 'q': query,
                                                        'limit': limit, 'resultId': result_id})
            portion = Parser(chunk, self._keys.get(collection_name, []),
                             self._iocs_keys.get(collection_name, []))
            result_id = portion._result_id
            date_from, date_to, query = None, None, None
            pytia_logger.info('{0} portion was loaded'.format(i))
            if portion.portion_size == 0:
                pytia_logger.info('Search session for {0} collection was finished, '
                                  'loaded {1} feeds'.format(collection_name, total_amount))
                break
            total_amount += portion.portion_size
            yield portion

    def search_feed_by_id(self, collection_name: str, feed_id: str):
        """
        Searches for feed with `feed_id` in collection with `collection_name`.

        :param collection_name: in what collection to search.
        :param feed_id: id of feed to search.
        :rtype: :class:`Parser`
        """
        Validator.validate_collection_name(collection_name)
        url = urljoin(self._api_url, collection_name + '/' + feed_id)
        chunk = self._send_request(url=url, params={})
        portion = Parser(chunk, self._keys.get(collection_name, []),
                         self._iocs_keys.get(collection_name, []))
        return portion

    def global_search(self, query: str) -> List[Dict[str, Any]]:
        """
        Global search across all collections with provided `query`, returns dict
        with information about collection, count, etc.

        :param query: in what collection to search.
        """
        url = urljoin(self._api_url, "search")
        response = self._send_request(url=url, params={"q": query})
        return response

    def search_file_in_threats(self, collection_name: str, feed_id: str, file_id: str) -> bytes:
        """
        Searches for file with `file_id` in collection with `collection_name` in feed with `feed_id`.

        .. warning:: `Collection_name` should be apt/threat or hi/threat.

        :param collection_name: in what collection to search.
        :param feed_id: id of feed with file to search.
        :param file_id: if of file to search.
        """
        Validator.validate_collection_name(collection_name)
        url = urljoin(self._api_url, collection_name + '/' + feed_id + '/file/' + file_id)
        binary_file = self._send_request(url=url, params={}, decode=False)
        return binary_file

    def get_seq_update_dict(self, date: Optional[str] = None) -> Dict[str, int]:
        """
        Gets dict with `seqUpdate` for all collections from server for provided date.
        If date is not provide returns dict for today.

        .. warning:: Date should be in "YYYY-MM-DD" format.

        :param date: defines for what date to get seqUpdate.
        :return: dict with collection names in keys and seq updates in values.
        """
        if date:
            Validator.validate_date_format(date=date, formats=["%Y-%m-%d"])

        req_url = urljoin(self._api_url, "sequence_list")
        params = {
            "date": date,
        }
        buffer_dict = self._send_request(url=req_url, params=params).get("list")
        seq_update_dict = {}
        for key in CollectionConsts.COLLECTIONS_INFO.keys():
            if key in buffer_dict.keys():
                seq_update_dict[key] = buffer_dict[key]
        return seq_update_dict

    def get_available_collections(self) -> List[str]:
        """
        Returns list of available collections.
        """
        seq_update_dict = self.get_seq_update_dict()
        collections_list = list(seq_update_dict.keys())
        collections_list.extend(CollectionConsts.ONLY_SEARCH_COLLECTIONS)
        return collections_list

    def close_session(self):
        """
        Closes the polling session. Use this function after finish polling to avoid problems.
        """
        self._session.close()


class Parser(object):
    """
    An object that handles raw JSON with various methods.

    :param dict chunk: data portion.
    :param dict[str, str] keys: fields to find in portion.
    :param dict[str, str] iocs_keys: IOCs to find in portion.
    """

    def __init__(self, chunk: Dict, keys: Dict[str, str], iocs_keys: Dict[str, str]):
        """
        :param chunk: data portion.
        :param keys: fields to find in portion.
        :param iocs_keys: IOCs to find in portion.
        """
        self.raw_dict = chunk
        self.raw_json = json.dumps(chunk)
        self.iocs_keys = iocs_keys
        self.keys = keys
        self.count = self.raw_dict.get('count', None)
        self.portion_size = len(self._return_items_list())
        self.sequpdate = self.raw_dict.get('seqUpdate', None)
        self._result_id = self.raw_dict.get('resultId', None)

    def _return_items_list(self):
        if self.count is not None:
            raw_dict = self.raw_dict.get('items', {})
        else:
            raw_dict = [self.raw_dict]
        return raw_dict

    def parse_portion(self, keys: Optional[Dict[any, str]] = None,
                      as_json: Optional[bool] = False) -> Union[str, List[Dict[Any, Any]]]:
        """
        Returns parsed portion of feeds using keys provided for current collection.
        Every dict in list is one parsed feed.

        :param keys: if provided override base keys set in poller.
        :param as_json: if True returns portion in JSON format.
        """
        if not self.keys and not keys:
            raise ParserException("You didn't provide any keys for parsing portion.")
        if keys:
            Validator.validate_set_keys_input(keys)
        parsed_portion = []
        raw_dict = self._return_items_list()
        for feed in raw_dict:
            parsed_dict = ParserHelper.find_by_template(feed, keys if keys else self.keys)
            parsed_portion.append(parsed_dict)

        if as_json:
            return json.dumps(parsed_portion)
        return parsed_portion

    def bulk_parse_portion(self, keys_list: List[Dict[any, str]],
                           as_json: Optional[bool] = False) -> Union[str, List[List[Dict[Any, Any]]]]:
        """
        Parses feeds in portion using every keys dict in the list.
        Every feed in parsed portion will be presented as list with parsed dicts for every keys dict.

        :param keys_list: list of keys dicts you want in return.
        :param as_json: if True returns portion in JSON format.
        """
        parsed_portion = []
        for keys in keys_list:
            parsed_portion.append(self.parse_portion(keys=keys))
        parsed_portion = [list(a) for a in zip(*parsed_portion)]

        if as_json:
            return json.dumps(parsed_portion)
        return parsed_portion

    def get_iocs(self, keys: Optional[Dict] = None,
                 as_json: Optional[bool] = False) -> Union[str, Dict[str, List]]:
        """
        Returns dict of IOCs parsed from portion of feeds for current collection.
        Keys are IOCs fields to search for current collection, values are list of IOCs for current portion.

        :param keys: if provided override base iocs_keys set in poller.
        :param as_json: if True returns iocs in JSON format.
        """
        if not self.iocs_keys and not keys:
            raise ParserException("You didn't provide any keys for getting IOCs.")
        if keys:
            Validator.validate_set_iocs_keys_input(keys)
            iocs_keys = keys
        else:
            iocs_keys = self.iocs_keys
        iocs_dict = {}
        raw_dict = self._return_items_list()
        for key, value in iocs_keys.items():
            iocs = []
            for feed in raw_dict:
                ioc = ParserHelper.find_element_by_key(obj=feed, key=value)
                iocs.extend(ParserHelper.unpack_iocs(ioc))

            iocs_dict[key] = iocs

        if as_json:
            return json.dumps(iocs_dict)
        return iocs_dict
