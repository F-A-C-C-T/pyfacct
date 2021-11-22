from datetime import datetime
from .exception import InputException
from .const import CollectionConsts
import logging


class Logger(object):
    # to catch logs from python libraries
    @staticmethod
    def init_root_logger():
        if not os.path.exists(LOGS_DIRECTORY):
            os.mkdir(LOGS_DIRECTORY)
        if os.path.exists("{0}/{1}".format(LOGS_DIRECTORY, CURRENT_SESSION_LOG_FILE)):
            os.remove("{0}/{1}".format(LOGS_DIRECTORY, CURRENT_SESSION_LOG_FILE))
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)
        console_handler = logging.StreamHandler()
        session_handler = logging.FileHandler(filename="{0}/{1}".format(LOGS_DIRECTORY, CURRENT_SESSION_LOG_FILE))
        all_time_handler = logging.FileHandler(filename="{0}/{1}".format(LOGS_DIRECTORY, ALL_TIME_LOG_FILE))
        console_handler.setLevel(logging.INFO)
        session_handler.setLevel(logging.DEBUG)
        all_time_handler.setLevel(logging.WARNING)

        console_format = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
        file_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(console_format)
        session_handler.setFormatter(file_format)
        all_time_handler.setFormatter(file_format)

        logger.addHandler(console_handler)
        logger.addHandler(session_handler)
        logger.addHandler(all_time_handler)
        return logger

    @staticmethod
    def init_logger(name=None):
        if not os.path.exists(LOGS_DIRECTORY):
            os.mkdir(LOGS_DIRECTORY)
        logger = logging.getLogger(name)
        logger.propagate = True
        return logger


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
    def validate_set_iocs_keys_input(cls, keys):
        if not isinstance(keys, dict):
            raise InputException("Keys should be stored in a dict")
        for i in keys.values():
            if not isinstance(i, str):
                raise InputException('Every search path should be a string')

    @classmethod
    def validate_set_keys_input(cls, keys):
        if isinstance(keys, dict):
            for i in keys.values():
                cls.validate_set_keys_input(i)
        elif not isinstance(keys, str):
            raise InputException('Keys should be stored in nested dicts and on the lower level it should be a string.')


class ParserHelper(object):
    @classmethod
    def find_by_template(cls, feed, keys):
        parsed_dict = {}
        for key, value in keys.items():
            if isinstance(value, str):
                if value.startswith("*"):
                    parsed_dict.update({key: value[1:]})
                else:
                    parsed_dict.update({key: cls.find_element_by_key(obj=feed, key=value)})
            elif isinstance(value, dict):
                parsed_dict.update({key: cls.find_by_template(feed, value)})

        return parsed_dict

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
