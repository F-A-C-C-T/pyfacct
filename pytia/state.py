import json
import pathlib
from typing import Union


class StateManager:
    def __init__(self) -> None:
        self.NAME_OF_STATE_FILE = ".state"
        self.state_stream = None
        self.state_file_entry = {}

    def __enter__(self) -> object:
        try:
            self.state_stream = open(self.NAME_OF_STATE_FILE, "r+")
        except FileNotFoundError:
            pathlib.Path(self.NAME_OF_STATE_FILE).touch()
            self.state_stream = open(self.NAME_OF_STATE_FILE, "r+")
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback) -> None:
        self.state_stream.close()

    def dump(self, name_of_collection: str, seq_update: int) -> None:
        self.state_stream.seek(0)
        self.state_file_entry[name_of_collection] = seq_update
        json.dump(self.state_file_entry, self.state_stream)
        self.state_stream.truncate()

    def load(self, name_of_collection: str) -> Union[int, None]:
        try:
            self.state_file_entry = json.load(self.state_stream)
        except json.decoder.JSONDecodeError:
            return None
        sequpdate = self.state_file_entry.get(name_of_collection)
        return sequpdate if sequpdate != 0 else None
