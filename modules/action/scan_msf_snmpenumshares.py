import re

from core.keystore import KeyStore
from core.msfActionModule import MsfActionModule


class scan_msf_snmpenumshares(MsfActionModule):
    def __init__(self, config, display, lock):
        super(scan_msf_snmpenumshares, self).__init__(config, display, lock)
        self.triggers = ["snmpCred"]
        self.requirements = ["msfconsole"]
        self.title = "Enumerate SMB Shares via LanManager OID Values"
        self.shortName = "MSFSNMPEnumShares"
        self.description = "execute [auxiliary/scanner/snmp/snmp_enumshares] on each target"
        self.safeLevel = 5

    def getTargets(self):
        # we are interested only in the hosts that have UDP 161 open
        self.targets = KeyStore.get('vuln/host/*/snmpCred')

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        if len(self.targets) > 0:
            # loop over each target
            for t in self.targets:
                # verify we have not tested this host before
                if not self.seentarget(t):
                    # add the new IP to the already seen list
                    self.addseentarget(t)

                    comStrings = KeyStore.get(f"vuln/host/{t}/snmpCred/communityString")
                    for comString in comStrings:
                        cmd = {'config': ["use auxiliary/scanner/snmp/snmp_enumshares", f"set RHOSTS {t}",
                                          f"set COMMUNITY {comString}"], 'payload': 'none'}

                        result, outfile = self.execute_msf(t, cmd)

                        #  Don't need to parse out IP, we are running module one IP at a time
                        # Just find lines with  -  and pull out share name
                        parts = re.findall(".* - .*", result)
                        for part in parts:
                            sharename = (part.split('-')[0]).strip()
                            KeyStore.add(f"share/smb/{t}/{sharename}")

        return
