from core.inputModule import InputModule
from core.keystore import KeyStore


class dictload(InputModule):
    def __init__(self, config, display, lock):
        super(dictload, self).__init__(config, display, lock)
        self.requirements = []
        self.title = "Load DICT Input File"
        self.description = "Load an DICT Input file"
        self.type = "dict"

    def process(self, input_file):
        contents = []
        with open(input_file, "r") as myfile:
            contents = myfile.readlines()

        for line in contents:
            parts = line.strip().split(':=')
            KeyStore.add(f"osint/{parts[0].lower()}/{parts[1]}")
            self.fire(f"new{parts[0]}")
        return
