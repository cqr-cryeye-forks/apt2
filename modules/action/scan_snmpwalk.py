from core.actionModule import actionModule
from core.keystore import KeyStore
from core.utils import Utils


class scan_snmpwalk(actionModule):
    def __init__(self, config, display, lock):
        super(scan_snmpwalk, self).__init__(config, display, lock)
        self.triggers = ["snmpCred"]
        self.requirements = ["snmpwalk"]
        self.title = "Run snmpwalk using found community string"
        self.shortName = "SNMPWalk"
        self.description = "execute [snmpwalk -v 2c -c COMMUNITY ip] on each target"
        self.safeLevel = 5

    def getTargets(self):
        # we are interested only in the hosts that have working snmp community strings
        self.targets = KeyStore.get('vuln/host/*/snmpCred')

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        if len(self.targets) > 0:
            # loop over each target
            for t in self.targets:
                if not self.seentarget(t):
                    # add the new IP to the already seen list
                    self.addseentarget(t)
                    cstrings = KeyStore.get(f"vuln/host/{t}/snmpCred/communityString")
                    for community in cstrings:
                        command = self.config["snmpwalk"] + " -v 2c -c " + community + " " + t
                        result = command + "\n" + Utils.execWait(command)  # append command to top of output
                        outfile = self.config["proofsDir"] + self.shortName + "_" + t + "_" + Utils.getRandStr(10)
                        Utils.writeFile(result, outfile)
                        KeyStore.add(f"host/{t}/vuln/snmpCred/output/" + outfile.replace("/", "%2F"))

        return
