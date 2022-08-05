import time
from multiprocessing.pool import ThreadPool

from core.events import EventHandler
from core.keystore import KeyStore
from core.packetcap import PktCapture


class actionModule(object):
    seen_targets = dict()

    def __init__(self, config, display, lock):
        self.display = display
        self.config = config
        self.safeLevel = 1
        self.targets = []
        self.title = ""
        self.shortName = ""
        self.triggers = []
        self.requirements = []
        self.description = ""
        self.vector = ""
        self.lock = lock
        self.maxThreads = 100
        self.types = []

    def getTitle(self):
        return self.title

    def getDescription(self):
        return self.description

    def getSafeLevel(self):
        return self.safeLevel

    def getTriggers(self):
        return self.triggers

    def getRequirements(self):
        return self.requirements

    def getTypes(self):
        return self.types

    def getShortName(self):
        return self.shortName

    def getTargets(self):
        return None

    def getMaxThreads(self):
        return self.maxThreads

    def getVector(self):
        return self.vector

    def process(self):
        return

    def go(self, vector):
        self.vector = vector
        self.display.verbose(f"-> Running : {self.getTitle()}")
        self.display.debug(f"---> {self.getDescription()}")
        return self.process()

    def fire(self, trigger):
        EventHandler.fire(f"{trigger}:{self.vector}-{self.shortName}")

    def getVectorDepth(self):
        return len(self.vector.split('-'))

    def pktCap(self, filter_str="", packetcount=10, timeout=60, srcip="", dstip=""):
        pool = ThreadPool(processes=1)
        p = PktCapture()

        # create new thread/process for the packet capture
        async_result = pool.apply_async(p.capture, (filter_str, timeout, packetcount, srcip, dstip,))

        # slepp for a second to allow everything to get set up
        time.sleep(1)

        return async_result

    def getPktCap(self, obj):
        return obj.get() if obj else ""

    def addseentarget(self, target):
        self.lock.acquire()
        if self.getShortName() not in actionModule.seen_targets:
            actionModule.seen_targets[self.getShortName()] = []
        if target not in actionModule.seen_targets[self.getShortName()]:
            actionModule.seen_targets[self.getShortName()].append(target)
        self.lock.release()

    def seentarget(self, target):
        self.lock.acquire()
        value = self.getShortName() in actionModule.seen_targets and target in actionModule.seen_targets[
            self.getShortName()]

        self.lock.release()
        return value

    def print_dict(self, d):
        return "".join(f"{key}: {key}\n" for key, value in d)

    def getDomainUsers(self, domain):
        return KeyStore.get(f'creds/domain/{domain}/username/')

    def getUsers(self, host):
        return KeyStore.get(f'creds/host/{host}/username/')

    def getHostnames(self, host):
        return KeyStore.get(f'host/{host}/hostname/')

    def addVuln(self, host, vuln, details=None):
        if details is None:
            details = {}
        self.display.error(f"VULN [{vuln}] Found on [{host}]")
        KeyStore.add(f"vuln/host/{host}/{vuln}/module/{self.shortName}/{self.vector}")

        for key in details:
            KeyStore.add(f"vuln/host/{host}/{vuln}/details/{key}/{details[key]}")
