"""

This module contains poller for GIB TI&A.

"""

import requests
import time
from datetime import datetime
import json
import logging
from urllib.parse import urljoin
import urllib
from requests.auth import HTTPBasicAuth
from typing import Union, Optional, List, Dict, Any, Generator
from .integration_exception import ConnectionException, InputException

gib_logger = logging.getLogger("gib_integration")


class TIAPoller(object):
    """
    Poller that can be used for requests to GIB TI&A.

    :param str username: Login for GIB TI&A.
    :param str api_key: API key, generated in GIB TI&A.
    :param str api_url: (optional) URL for GIB TI&A.
    """
    def __init__(self, username: str, api_key: str, api_url: str = 'https://tap.group-ib.com/api/v2/'):
        """
        :param username: Login for GIB TI&A.
        :param api_key: API key, generated in GIB TI&A.
        :param api_url: (optional) URL for GIB TI&A.
        """
        self._api_url = api_url
        self._session = requests.Session()
        self._keys = {"compromised/account": [], "compromised/card": [], "compromised/mule": [],
                      "compromised/imei": [], "attacks/ddos": [],
                      "attacks/phishing": [], "attacks/phishing_kit": [],
                      "attacks/deface": [], "suspicious_ip/tor_node": [], "suspicious_ip/open_proxy": [],
                      "suspicious_ip/socks_proxy": [], "malware/targeted_malware": [], "malware/malware": [],
                      "malware/cnc": [], "osi/public_leak": [], "osi/git_leak": [],
                      "osi/vulnerability": [], "apt/threat_actor": [], "apt/threat": [],
                      "bp/phishing": [], "bp/phishing_kit": [], "hi/threat": [], "hi/threat_actor": []}
        self._iocs_keys = {"compromised/account": ['client.ipv4.ip', 'cnc.domain', 'cnc.url', 'cnc.ipv4.ip', 'login'],
                           "compromised/card": ['client.ipv4.ip', 'cnc.domain',
                                                'cnc.url', 'cnc.ipv4.ip', 'cardInfo.number'],
                           "compromised/mule": ['account', 'cnc.domain', 'cnc.url', 'cnc.ipv4.ip'],
                           "compromised/imei": ['client.ipv4.ip', 'cnc.domain',
                                                'cnc.url', 'cnc.ipv4.ip', 'device.imei'],
                           "attacks/ddos": ['cnc.domain', 'cnc.url', 'cnc.ipv4.ip',
                                            'target.ipv4.ip', 'target.url', 'target.domain'],
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
                                               'indicators.params.domain', 'indicators.params.ipv4']}
        self._session.auth = HTTPBasicAuth(username, api_key)
        self._session.headers.update({"Accept": "*/*"})
        self._session.verify = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._session.close()

    def _validate_input_data(self, collection_name, limit, date_from, date_to):
        if collection_name not in self._keys:
            raise InputException('Invalid collection name {0}'.format(collection_name))
        if limit > 400:
            raise InputException('Max limit=400, your limit={0}'.format(limit))
        if collection_name in ['hi/threat', 'apt/threat', 'osi/public_leak', 'suspicious_ip/tor_node']:
            if limit > 100:
                gib_logger.warning('For collection {0} recommended limit=100'.format(collection_name))
        elif limit > 200:
            gib_logger.warning('For collection {0} recommended limit=200'.format(collection_name))
        try:
            if date_from:
                if len(date_from) == 10:
                    datetime.strptime(date_from, '%Y-%m-%d')
                else:
                    datetime.strptime(date_from, '%Y-%m-%dT%H:%M:%S%z')
            if date_to:
                if len(date_to) == 10:
                    datetime.strptime(date_to, '%Y-%m-%d')
                else:
                    datetime.strptime(date_to, '%Y-%m-%dT%H:%M:%S%z')
        except TypeError or ValueError as e:
            gib_logger.exception('Invalid date.')
            raise InputException("""Invalid date, please use one of this formats: "YYYY-MM-DD", "YYYY-MM-DDThh:mm:ssZ" 
                                 or "YYYY-MM-DDThh:mm:ss+-hh:mm". Exception message: {0}""". format(e))

    def _send_request(self, url, params, decode=True):
        params = {k: v for k, v in params.items() if v}
        status_codes_msgs = {
            401: "Bad Credentials",
            403: "Something is wrong with your account, please, contact GIB.",
            404: "Not found. There is no such data on server.",
            500: "There are some troubles on server with your request.",
            301: "Verify that your public IP is whitelisted by Group IB.",
            302: "Verify that your public IP is whitelisted by Group IB.",
            429: "Maximum count of requests per second reached, please, increase limits in configuration file."
        }
        timeout_exception = ''
        for i in range(10):
            try:
                response = self._session.get(url, params=params, timeout=60)
                status_code = response.status_code
                if status_code == 200:
                    if decode:
                        return response.json()
                    else:
                        return response.content
            except requests.exceptions.Timeout as e:
                timeout_exception = str(e)
            time.sleep(1)
        if timeout_exception:
            raise ConnectionException("Max retries reached. Last exception: " + timeout_exception)
        elif status_code in status_codes_msgs:
            raise ConnectionException("Max retries reached. Last status code: {0}. "
                                      "Message: {1}".format(status_code, status_codes_msgs[status_code]))
        else:
            raise ConnectionException("Max retries reached. Last status code: " +
                                      str(status_code) + ". Something wrong.")

    def set_proxies(self, proxies: dict):
        """
        Sets proxies for `Session` object.

        :param proxies: requests-like proxies.
        """
        self._session.proxies = proxies

    def set_keys(self, collection_name: str, keys: List[str]):
        """
        Sets keys to search in the selected collection. Parser finds keys recursively in lists/dicts
        so set keys in this format: ``firstkey.secondkey``.

        :param collection_name: name of the collection whose keys to set.
        :param keys: list of keys to get from parse.
        """
        if collection_name in self._keys.keys():
            if isinstance(keys, list):
                for i in keys:
                    if not isinstance(i, str):
                        raise InputException('Every key should be a string')
                self._keys[collection_name] = keys
            else:
                raise InputException("Keys should be stored in a list")
        else:
            raise InputException('Invalid collection name {0}, '
                                 'should be one of this {1}'.format(collection_name, list(self._keys.keys())))

    def set_iocs_keys(self, collection_name: str, keys: List[str]):
        """
        Sets keys to search IOCs in the selected collection. Parser finds keys recursively in lists/dicts
        so set keys in this format: ``firstkey.secondkey``. Most of the IOCs keys are set by default.

        :param collection_name: name of the collection whose keys to set.
        :param keys: list of keys to get from parse.
        """
        if collection_name in self._iocs_keys.keys():
            if isinstance(keys, list):
                for i in keys:
                    if not isinstance(i, str):
                        raise InputException('Every key should be a string')
                self._iocs_keys[collection_name] = keys
            else:
                raise InputException("Keys should be stored in a list")
        else:
            raise InputException('Invalid collection name {0}, '
                                 'should be one of this {1}'.format(collection_name, list(self._keys.keys())))

    def create_update_generator(self, collection_name: str, date_from: Optional[str] = None,
                                date_to: Optional[str] = None, query: Optional[str] = None,
                                sequpdate: Union[int, str] = None, limit: Union[int, str] = 200):
        """
        Creates generator of :class:`Parser` class objects for an update session
        (feeds are sorted in ascending order) for `collection_name` with set parameters.

        Recommended limit for `hi/threat`, `apt/threat`, `osi/public_leak`, `suspicious_ip/tor_node` is 100, for other collections - 200.

        `sequpdate` allows you to receive all relevant feeds. Such a request uses the sequpdate parameter, you will receive a portion of feeds that starts with the next `sequpdate` parameter for the current collection.
        For all feeds in the Group IB Intelligence continuous numbering is carried out.
        For example, the `sequpdate` equal to 1999998 can be in the `compromised/accounts` collection, and a feed with sequpdate equal to 1999999 can be in the `attacks/ddos` collection.
        If item updates (for example, if new attacks were associated with existing APT by our specialists or tor node has been detected as active again), the item gets a new parameter and it automatically rises in the database and "becomes relevant" again.

        .. warning:: Dates should be in one of this formats: "YYYY-MM-DD", "YYYY-MM-DDThh:mm:ssZ" or "YYYY-MM-DDThh:mm:ss+-hh:mm". Limit shouldn't be higher than 400.

        :param collection_name: collection to update.
        :param date_from: start date of update session.
        :param date_to: end date of update session.
        :param query: query to search during update session.
        :param sequpdate: identification number from which to start the session.
        :param limit: size of portion in iteration.
        :rtype: Generator[:class:`Parser`]
        """
        gib_logger.info('Starting update session for {0} collection'.format(collection_name))
        limit = int(limit)
        self._validate_input_data(collection_name, limit, date_from, date_to)
        url = urljoin(self._api_url, collection_name + '/updated')
        try:
            i = 0
            j = 0
            final_portion_count = 0
            while True:
                gib_logger.info('Loading {0} portion, starting from sequpdate={1}'.format(i+1, sequpdate))
                chunk = self._send_request(url=url, params={'df': date_from, 'dt': date_to, 'q': query,
                                                            'limit': limit, 'seqUpdate': sequpdate})
                portion = Parser(chunk, self._keys.get(collection_name),
                                 self._iocs_keys.get(collection_name))
                sequpdate = portion.sequpdate
                date_from = None
                if portion.count == 0:
                    gib_logger.info('Update session for {0} collection was finished, '
                                    'loaded {1} feeds'.format(collection_name, (i-j) * limit + final_portion_count))
                    break
                elif portion.count < limit:
                    final_portion_count += portion.count
                    j += 1
                    time.sleep(1)
                i += 1
                gib_logger.info('{0} portion was loaded'.format(i))
                yield portion
        finally:
            self._session.close()

    def create_search_generator(self, collection_name: str, date_from: str = None, date_to: Optional[str] = None,
                                query: Optional[str] = None, limit: Union[str, int] = 200):
        """
        Creates generator of :class:`Parser` class objects for the search session 
        (feeds are sorted in descending order) for `collection_name` with set parameters.

        Recommended limit for `hi/threat`, `apt/threat`, `osi/public_leak`, `suspicious_ip/tor_node` is 100, for other collections - 200.

        .. warning:: Dates should be in one of this formats: "YYYY-MM-DD", "YYYY-MM-DDThh:mm:ssZ" or "YYYY-MM-DDThh:mm:ss+-hh:mm". Limit shouldn't be higher than 400.

        :param collection_name: collection to search.
        :param date_from: start date of search session.
        :param date_to: end date of search session.
        :param query: query to search during session.
        :param limit: size of portion in iteration.
        :rtype: Generator[:class:`Parser`]
        """
        gib_logger.info('Starting search session for {0} collection'.format(collection_name))
        limit = int(limit)
        self._validate_input_data(collection_name, limit, date_from, date_to)
        result_id = None
        url = urljoin(self._api_url, collection_name)
        try:
            i = 0
            j = 0
            final_portion_count = 0
            while True:
                gib_logger.info('Loading {0} portion'.format(i+1))
                chunk = self._send_request(url=url, params={'df': date_from, 'dt': date_to, 'q': query,
                                                            'limit': limit, 'resultId': result_id})
                portion = Parser(chunk, self._keys.get(collection_name),
                                 self._iocs_keys.get(collection_name))
                result_id = portion._result_id
                date_from, date_to, query = None, None, None

                if len(portion.raw_dict.get('items')) == 0:
                    gib_logger.info('Search session for {0} collection was finished, '
                                    'loaded {1} feeds'.format(collection_name, (i-j) * limit + final_portion_count))
                    break
                elif len(portion.raw_dict.get('items')) < limit:
                    final_portion_count += len(portion.raw_dict.get('items'))
                    j += 1
                    time.sleep(1)
                i += 1
                logger.info('{0} portion was loaded'.format(i))
                yield portion
        finally:
            self._session.close()

    def search_feed_by_id(self, collection_name: str, feed_id: str):
        """
        Searches for feed with `feed_id` in collection with `collection_name`.

        :param collection_name: in what collection to search.
        :param feed_id: id of feed to search.
        :rtype: :class:`Parser`
        """
        try:
            url = urljoin(self._api_url, collection_name + '/' + feed_id)
            chunk = self._send_request(url=url, params={})
            portion = Parser(chunk, self._keys.get(collection_name),
                             self._iocs_keys.get(collection_name))
            return portion
        finally:
            self._session.close()

    def search_file_in_threats(self, collection_name: str, feed_id: str, file_id: str) -> bytes:
        """
        Searches for file with `file_id` in collection with `collection_name` in feed with `feed_id`.

        .. warning:: `Collection_name` should be apt/threat or hi/threat.

        :param collection_name: in what collection to search.
        :param feed_id: id of feed with file to search.
        :param file_id: if of file to search.
        """
        try:
            url = urljoin(self._api_url, collection_name + '/' + feed_id + '/file/' + file_id)
            binary_file = self._send_request(url=url, params={}, decode=False)
            return binary_file
        finally:
            self._session.close()

    def get_seq_update_dict(self, date: Optional[str] = None) -> Dict[str, int]:
        """
        Gets dict with `seqUpdate` for all collections from server for provided date.
        If date is not provide returns dict for today.

        .. warning:: Date should be in "YYYY-MM-DD" format.

        :param date: defines for what date to get seqUpdate.
        :return: dict with collection names in keys and seq updates in values.
        """
        if date is not None:
            try:
                datetime.strptime(date, '%Y-%m-%d')
            except TypeError or ValueError as e:
                gib_logger.exception('Invalid date for get_seq_update_dict.')
                raise InputException("""Invalid date for get_seq_update_dict. , please use "YYYY-MM-DD" format. 
                                     Exception message: {0}""".format(e))

        req_url = urljoin(self._api_url, "sequence_list")
        params = {
            "date": date,
        }
        buffer_dict = self._send_request(url=req_url, params=params).get("list")
        seq_update_dict = {}
        for key in self._keys.keys():
            if key in buffer_dict.keys():
                seq_update_dict[key] = buffer_dict[key]
        return seq_update_dict

    def get_available_collections(self) -> List[str]:
        """
        Returns list of available collections.
        """
        seq_update_dict = self.get_seq_update_dict()
        collections_list = list(seq_update_dict.keys())
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
    :param list[str] keys: fields to find in portion.
    :param list[str] iocs_keys: IOCs to find in portion.
    """

    def __init__(self, chunk: Dict, keys: List[str], iocs_keys: List[str]):
        """
        :param chunk: data portion.
        :param keys: fields to find in portion.
        :param iocs_keys: IOCs to find in portion.
        """
        self.raw_dict = chunk
        self.iocs_keys = iocs_keys
        self.keys = keys
        self.raw_json = json.dumps(chunk)
        self._result_id = self.raw_dict.get('resultId', None)
        self.count = self.raw_dict.get('count', None)
        self.sequpdate = self.raw_dict.get('seqUpdate', None)

    def __find_element_by_key(self, obj, key):
        """
        Recursively finds element or elements in dict.
        """
        path = key.split(".", 1)
        if len(path) == 1:
            if isinstance(obj, list):
                return [i.get(path[0]) for i in obj]
            elif isinstance(obj, dict):
                return obj.get(path[0])
            else:
                return obj
        else:
            if isinstance(obj, list):
                return [self.__find_element_by_key(i.get(path[0]), path[1]) for i in obj]
            elif isinstance(obj, dict):
                return self.__find_element_by_key(obj.get(path[0]), path[1])
            else:
                return obj

    def __unpack_iocs(self, ioc):
        """
        Recursively unpacks all IOCs in one list.
        """
        unpacked = []
        if isinstance(ioc, list):
            for i in ioc:
                unpacked.extend(self.__unpack_iocs(i))
            return unpacked
        else:
            if ioc in ['255.255.255.255', '0.0.0.0', '', None]:
                return [ioc]
            else:
                return []

    def _return_items_list(self):
        if self.count is not None:
            raw_dict = self.raw_dict.get('items', {})
        else:
            raw_dict = [self.raw_dict]
        return raw_dict

    def parse_portion(self, as_json: Optional[bool] = False) -> Union[str, List[Dict[str, Any]]]:
        """
        Returns parsed portion of feeds using keys provided for current collection. Every dict in list is one parsed feed.

        For example:
        Key `iocs.network.ip` for feed: `{'iocs': {'network': [{'ip': [1, 2, 3]}]}}` will return this `{iocs_network_ip: [[1, 2, 3]]}`.

        :param as_json: if True returns portion in JSON format.
        """
        parsed_portion = []
        raw_dict = self._return_items_list()
        for feed in raw_dict:
            parsed_dict = {}
            for key in self.keys:
                parsed_dict.update({key: self.__find_element_by_key(feed, key)})
            parsed_portion.append(parsed_dict)
        if as_json:
            return json.dumps(parsed_portion)
        return parsed_portion

    def get_iocs(self, as_json: Optional[bool] = False) -> Union[str, Dict[str, List]]:
        """
        Returns dict of IOCs parsed from portion of feeds for current collection. Keys are IOCs fields to search for current collection,
        values are list of IOCs for current portion.

        :param as_json: if True returns iocs in JSON format.
        """
        iocs_dict = {}
        raw_dict = self._return_items_list()
        for key in self.iocs_keys:
            iocs = []
            for feed in raw_dict:
                ioc = self.__find_element_by_key(feed, key)
                iocs.extend(self.__unpack_iocs(ioc))
            iocs_dict[key] = iocs
        if as_json:
            return json.dumps(iocs_dict)
        return iocs_dict
