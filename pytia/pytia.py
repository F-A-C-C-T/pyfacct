"""

This module contains poller for GIB TI&A.

"""

from dataclasses import dataclass
import json
import logging
from urllib.parse import urljoin, urlencode
from typing import Union, Optional, List, Dict, Any, Generator

import requests
from requests.auth import HTTPBasicAuth
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

from .exception import ConnectionException, ParserException
from .const import *
from .utils import Validator, ParserHelper

logger = logging.getLogger(__name__)


@dataclass(order=True)
class GeneratorInfo(object):
    collection_name: str
    session_type: str
    date_from: str = None
    date_to: Optional[str] = None
    query: Optional[str] = None
    limit: Union[str, int] = None
    apply_hunting_rules: Union[int, str] = None
    keys: Optional[Dict[any, str]] = None
    iocs_keys: Optional[Dict] = None

    def __validate_default_fields(self) -> None:
        """
        Function for field validation. This function must always be called in __post_init__.
        """
        Validator.validate_collection_name(self.collection_name, method=self.session_type)
        if self.date_from:
            Validator.validate_date_format(
                date=self.date_from,
                formats=CollectionConsts.COLLECTIONS_INFO.get(self.collection_name).get("date_formats")
            )
        if self.date_to:
            Validator.validate_date_format(
                date=self.date_to,
                formats=CollectionConsts.COLLECTIONS_INFO.get(self.collection_name).get("date_formats")
            )
        # todo: прикрутить нормальную проверку
        if self.limit:
            int(self.limit)

    def __post_init__(self) -> None:
        """

        This function is called after __init__ and is used to validate input data.
        """
        self.__validate_default_fields()


class TIAPoller(object):
    """
    Poller that can be used for requests to GIB TI&A.

    :param str username: Login for GIB TI&A.
    :param str api_key: API key, generated in GIB TI&A.
    :param str api_url: (optional) URL for GIB TI&A.
    """
    def __init__(self, username: str, api_key: str, api_url: Optional[str] = RequestConsts.API_URL):
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

    def _status_code_handler(self, response):
        status_code = response.status_code
        if status_code == 200:
            return
        elif status_code in RequestConsts.STATUS_CODE_MSGS:
            raise ConnectionException(
                f"Status code: {status_code}. Message: {RequestConsts.STATUS_CODE_MSGS[status_code]}"
            )
        else:
            raise ConnectionException(
                f"Something wrong. Status code: {status_code}. Response body: {response.text}."
            )

    def send_request(self, endpoint, params, decode=True, **kwargs):
        url = urljoin(self._api_url, endpoint)
        params = urlencode({k: v for k, v in params.items() if v})
        try:
            response = self._session.get(url, params=params, timeout=RequestConsts.TIMEOUT,
                                         proxies=self._session.proxies)
            self._status_code_handler(response)
            if decode:
                return response.json()
            return response.content
        except requests.exceptions.Timeout as e:
            raise ConnectionException(f"Max retries reached. Exception message: {e}")

    def set_proxies(self, proxies: dict):
        """
        Sets proxies for `Session` object.

        :param proxies: requests-like proxies.
        """
        self._session.proxies = proxies

    def set_verify(self, verify: Union[bool, str]):
        """
        Sets verify for `Session` object.

        :param verify: Either a boolean, in which case it controls whether we verify
            the server's TLS certificate, or a string, in which case it must be a path
            to a CA bundle to use. Defaults to ``True``. When set to
            ``False``, requests will accept any TLS certificate presented by
            the server, and will ignore hostname mismatches and/or expired
            certificates, which will make your application vulnerable to
            man-in-the-middle (MitM) attacks. Setting verify to ``False``
            may be useful during local development or testing.
        """
        self._session.verify = verify

    def set_product(self, product_name: str, product_version: str = "", integration_version: str = ""):
        self._session.headers["User-Agent"] = f"pytia/{TechnicalConsts.library_version} " \
                                              f"{product_name}/{product_version} {integration_version}"

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
                                sequpdate: Union[int, str] = None, limit: Union[int, str] = None,
                                apply_hunting_rules: Union[int, str] = None):
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

        .. warning:: Dates should be in one of this formats: "YYYY-MM-DD", "YYYY-MM-DDThh:mm:ssZ".
        For most collections, limits are set on the server and can't be exceeded.

        :param collection_name: collection to update.
        :param date_from: start date of update session.
        :param date_to: end date of update session.
        :param query: query to search during update session.
        :param sequpdate: identification number from which to start the session.
        :param limit: size of portion in iteration.
        :param apply_hunting_rules: apply or not client hunting rules to get only filtered data (applicable for public_leak, phishing_group and breached)
        :rtype: Generator[:class:`Parser`]
        """
        session_type = "update"
        generator_info = GeneratorInfo(collection_name, session_type, date_from, date_to, query, limit,
                                       apply_hunting_rules, keys=self._keys.get(collection_name),
                                       iocs_keys=self._iocs_keys.get(collection_name))
        generator_class = UpdateFeedGenerator(self, generator_info, sequpdate=sequpdate)
        return generator_class.create_generator()

    def create_search_generator(self, collection_name: str, date_from: str = None, date_to: Optional[str] = None,
                                query: Optional[str] = None, limit: Union[str, int] = None,
                                apply_hunting_rules: Union[int, str] = None):
        """
        Creates generator of :class:`Parser` class objects for the search session 
        (feeds are sorted in descending order, **excluding compromised/breached amd compromised/reaper**)
        for `collection_name` with set parameters.

        .. warning:: Dates should be in one of this formats: "YYYY-MM-DD", "YYYY-MM-DDThh:mm:ssZ".
        For most collections, limits are set on the server and can't be exceeded.

        :param collection_name: collection to search.
        :param date_from: start date of search session.
        :param date_to: end date of search session.
        :param query: query to search during session.
        :param limit: size of portion in iteration.
        :param apply_hunting_rules: apply or not client hunting rules to get only filtered data (applicable for public_leak, phishing_group and breached)
        :rtype: Generator[:class:`Parser`]
        """
        session_type = "search"
        generator_info = GeneratorInfo(collection_name, session_type, date_from, date_to, query, limit,
                                       apply_hunting_rules, keys=self._keys.get(collection_name),
                                       iocs_keys=self._iocs_keys.get(collection_name))
        generator_class = SearchFeedGenerator(self, generator_info)
        return generator_class.create_generator()

    def search_feed_by_id(self, collection_name: str, feed_id: str):
        """
        Searches for feed with `feed_id` in collection with `collection_name`.

        :param collection_name: in what collection to search.
        :param feed_id: id of feed to search.
        :rtype: :class:`Parser`
        """
        Validator.validate_collection_name(collection_name)
        endpoint = f"{collection_name}/{feed_id}"
        chunk = self.send_request(endpoint=endpoint, params={})
        portion = Parser(chunk, self._keys.get(collection_name, []),
                         self._iocs_keys.get(collection_name, []))
        return portion

    def search_file_in_threats(self, collection_name: str, feed_id: str, file_id: str) -> bytes:
        """
        Searches for file with `file_id` in collection with `collection_name` in feed with `feed_id`.

        .. warning:: `Collection_name` should be apt/threat or hi/threat.

        :param collection_name: in what collection to search.
        :param feed_id: id of feed with file to search.
        :param file_id: if of file to search.
        """
        Validator.validate_collection_name(collection_name)
        endpoint = f"{collection_name}/{feed_id}/file/{file_id}"
        binary_file = self.send_request(endpoint=endpoint, params={}, decode=False)
        return binary_file

    def execute_action_by_id(self, collection_name: str, feed_id: str, action: str,
                             request_params: Optional[Dict] = None, decode: Optional[bool] = True):
        """
        Executes `action` for feed with `feed_id` in collection `collection_name`.

        :param collection_name: in what collection to search.
        :param feed_id: id of feed to search.
        :param action: action to execute (part of REST resource after "action/")
        :param request_params: dict of params to send with this request (e.g.: {"url_id": "1342312"})
        :param decode: True to get data in json format, False to get raw content
        """
        Validator.validate_collection_name(collection_name)
        if action[0] == "/":
            action = action[1::]
        endpoint = f"{collection_name}/{feed_id}/action/{action}"
        response = self.send_request(endpoint=endpoint, params=request_params, decode=decode)
        return response

    def global_search(self, query: str) -> List[Dict[str, Any]]:
        """
        Global search across all collections with provided `query`, returns dict
        with information about collection, count, etc.

        :param query: query to search for.
        """
        endpoint = "search"
        response = self.send_request(endpoint=endpoint, params={"q": query})
        return response

    def get_seq_update_dict(self, date: Optional[str] = None,
                            apply_hunting_rules: Union[int, str] = None) -> Dict[str, int]:
        """
        Gets dict with `seqUpdate` for all collections from server for provided date.
        If date is not provide returns dict for today.

        .. warning:: Date should be in "YYYY-MM-DD" format.

        :param date: defines for what date to get seqUpdate.
        :param apply_hunting_rules: apply or not client hunting rules to get only filtered data (applicable for public_leak, phishing_group and breached)
        :return: dict with collection names in keys and seq updates in values.
        """
        if date:
            Validator.validate_date_format(date=date, formats=["%Y-%m-%d"])

        endpoint = "sequence_list"
        params = {"date": date, "apply_hunting_rules": apply_hunting_rules}
        buffer_dict = self.send_request(endpoint=endpoint, params=params).get("list")
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
        for collection_name in CollectionConsts.ONLY_SEARCH_COLLECTIONS:
            try:
                self.send_request(endpoint=collection_name, params={})
                collections_list.append(collection_name)
            except Exception as e:
                pass
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

    def __init__(self, chunk: Dict, keys: Dict[any, str], iocs_keys: Dict[str, str]):
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


class FeedGenerator(object):
    def __init__(self, poller_object: TIAPoller, generator_info: GeneratorInfo):
        self.i = 0
        self.total_amount = 0
        self.poller_object = poller_object
        self.generator_info = generator_info
        self.endpoint = self.generator_info.collection_name

    def _get_params(self):
        return {'df': self.generator_info.date_from, 'dt': self.generator_info.date_to,
                'q': self.generator_info.query, 'limit': self.generator_info.limit,
                "apply_hunting_rules": self.generator_info.apply_hunting_rules}

    def _reset_params(self, portion):
        pass

    def create_generator(self):
        logger.info(f"Starting {self.generator_info.session_type} "
                    f"session for {self.generator_info.collection_name} collection")

        while True:
            self.i += 1
            logger.info(f"Loading {self.i} portion")
            chunk = self.poller_object.send_request(endpoint=self.endpoint, params=self._get_params())
            portion = Parser(chunk, self.generator_info.keys, self.generator_info.iocs_keys)
            logger.info(f"{self.i} portion was loaded")
            if portion.portion_size == 0:
                logger.info(f"{self.generator_info.session_type} session for {self.generator_info.collection_name} "
                            f"collection was finished, loaded {self.total_amount} feeds")
                break
            self.total_amount += portion.portion_size
            self._reset_params(portion)
            yield portion


class UpdateFeedGenerator(FeedGenerator):
    def __init__(self, poller_object: TIAPoller, generator_info: GeneratorInfo, sequpdate):
        super().__init__(poller_object, generator_info)
        self.sequpdate = sequpdate
        self.endpoint = f"{self.generator_info.collection_name}/updated"

    def _get_params(self):
        return {**super()._get_params(), "seqUpdate": self.sequpdate}

    def _reset_params(self, portion):
        self.sequpdate = portion.sequpdate
        self.generator_info.date_from = None


class SearchFeedGenerator(FeedGenerator):
    def __init__(self, poller_object: TIAPoller, generator_info: GeneratorInfo):
        super().__init__(poller_object, generator_info)
        self.result_id = None

    def _get_params(self):
        return {**super()._get_params(), "resultId": self.result_id}

    def _reset_params(self, portion):
        self.result_id = portion._result_id
        self.generator_info.date_from, self.generator_info.date_to, self.generator_info.query = None, None, None
