from datetime import datetime
from .exception import InputException
from .const import *


class Validator(object):
    @classmethod
    def validate_collection_name(cls, collection_name):
        if collection_name not in COLLECTIONS_INFO.keys():
            raise InputException('Invalid collection name {0}, '
                                 'should be one of this {1}'.format(collection_name, ", ".join(COLLECTIONS_INFO.keys())))

    @classmethod
    def validate_date_format(cls, date, formats):
        flag = 1
        for i in formats:
            try:
                datetime.strptime(date, i)
                flag = 0
                break
            except (TypeError, ValueError):
                pass
        if flag:
            raise InputException("""Invalid date, please use one of this formats: {0}.""".format(', '.join(formats)))

    @classmethod
    def validate_set_keys_input(cls, keys):
        if not isinstance(keys, list):
            raise InputException("Keys should be stored in a list")
        for i in keys:
            if not isinstance(i, str):
                raise InputException('Every key should be a string')


class ParserHelper(object):
    @classmethod
    def find_element_by_key(cls, obj, key):
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
                return [cls.find_element_by_key(i.get(path[0]), path[1]) for i in obj]
            elif isinstance(obj, dict):
                return cls.find_element_by_key(obj.get(path[0]), path[1])
            else:
                return obj

    @classmethod
    def unpack_iocs(cls, ioc):
        """
        Recursively unpacks all IOCs in one list.
        """
        unpacked = []
        if isinstance(ioc, list):
            for i in ioc:
                unpacked.extend(cls.unpack_iocs(i))
            return unpacked
        else:
            if ioc not in ['255.255.255.255', '0.0.0.0', '', None]:
                return [ioc]
            else:
                return []
