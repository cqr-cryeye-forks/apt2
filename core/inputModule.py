from core.events import EventHandler


class InputModule(object):
    def __init__(self, config, display, lock):
        self.display = display
        self.config = config
        self.title = ""
        self.requirements = []
        self.description = ""
        self.type = ""
        self.lock = lock

    def getType(self):
        return self.type

    def getTitle(self):
        return self.title

    def getDescription(self):
        return self.description

    def getRequirements(self):
        return self.requirements

    def process(self, input_file):
        return

    def go(self, input_file):
        self.display.verbose(f"-> Running : {self.getTitle()}")
        return self.process(input_file)

    def fire(self, trigger):
        EventHandler.fire(f"{trigger}:INPUTFile")
