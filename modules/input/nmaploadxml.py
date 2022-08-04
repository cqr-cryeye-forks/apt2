from core.inputModule import InputModule
from core.mynmap import MyNmap


class nmaploadxml(InputModule):
    def __init__(self, config, display, lock):
        super(nmaploadxml, self).__init__(config, display, lock)
        self.requirements = ["nmap"]
        self.title = "Load NMap XML File"
        self.description = "Load an NMap XML file"
        self.type = "nmap"

    def process(self, input_file):
        n = MyNmap(self.config, self.display)
        n.loadXMLFile(input_file, "nmapFile")
        return
