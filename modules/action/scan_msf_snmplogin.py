import re

from core.keystore import KeyStore
from core.msfActionModule import MsfActionModule


class scan_msf_snmplogin(MsfActionModule):
    def __init__(self, config, display, lock):
        super(scan_msf_snmplogin, self).__init__(config, display, lock)
        self.triggers = ["newPort_tcp_161"]
        self.requirements = ["msfconsole"]
        self.title = "Attempt Login Using Common Community Strings"
        self.shortName = "MSFSNMPLogin"
        self.description = "execute [auxiliary/scanner/snmp/snmp_login] on each target"
        self.safeLevel = 5

    def getTargets(self):
        # we are interested only in the hosts that have UDP 161 open
        self.targets = KeyStore.get('port/udp/161')

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        if len(self.targets) > 0:
            # If any results are successful, this will become true and fire will be called in the end
            callFire = False
            # loop over each target
            for t in self.targets:
                # verify we have not tested this host before
                if not self.seentarget(t):
                    # add the new IP to the already seen list
                    self.addseentarget(t)

                    cmd = {'config': ["use auxiliary/scanner/snmp/snmp_login", f"set RHOSTS {t}", "set VERSION 2c"],
                           'payload': 'none'}

                    result, outfile = self.execute_msf(t, cmd)

                    parts = re.findall(".*LOGIN SUCCESSFUL.*", result)
                    for part in parts:
                        callFire = True
                        # Add all relevant details
                        p = part.split()
                        comString = p[p.index("SUCCESSFUL:") + 1]
                        self.addVuln(t, "snmpCred", {"port": "161", "message": str(part), "communityString": comString,
                                                     "output": outfile.replace("/", "%2F")})

            if callFire:
                self.fire("snmpCred")

        return
