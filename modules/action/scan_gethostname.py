import contextlib
import socket

from core.actionModule import actionModule
from core.keystore import KeyStore


class scan_gethostname(actionModule):
    def __init__(self, config, display, lock):
        super(scan_gethostname, self).__init__(config, display, lock)
        self.title = "Determine the hostname for each IP"
        self.shortName = "GetHostname"
        self.description = "execute [gethostbyaddr(ip)] on each target"

        self.requirements = []
        self.triggers = ["newIP"]

        self.safeLevel = 5

    def getTargets(self):
        # get all hosts
        self.targets = KeyStore.get('host')

    def process(self):
        self.getTargets()
        for t in self.targets:
            if not self.seentarget(t):
                self.addseentarget(t)
                self.display.verbose(f"{self.shortName} - Connecting to {t}")
                with contextlib.suppress(Exception):
                    results = socket.gethostbyaddr(t)
                    self.fire("newHostname")
                    KeyStore.add(f'host/{t}/hostname/{results[0]}')
        return
