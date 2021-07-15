from datetime import datetime
from .exception import InputException
from .const import CollectionConsts


class Validator(object):
    @classmethod
    def validate_collection_name(cls, collection_name, method=None):
        if method == "update" and collection_name in CollectionConsts.ONLY_SEARCH_COLLECTIONS:
            raise InputException("{0} collection must be used only with a search generator.".format(collection_name))
        collection_names = CollectionConsts.COLLECTIONS_INFO.keys()
        if collection_name not in collection_names:
            raise InputException('Invalid collection name {0}, '
                                 'should be one of this {1}'.format(collection_name, ", ".join(collection_names)))

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
        if not isinstance(keys, dict):
            raise InputException("Keys should be stored in a dict")
        for i in keys.values():
            if not isinstance(i, str):
                raise InputException('Every search path should be a string')


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
        else:
            if ioc not in ['255.255.255.255', '0.0.0.0', '', None]:
                unpacked.append(ioc)

        return unpacked
