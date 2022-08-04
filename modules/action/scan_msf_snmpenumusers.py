import re

from core.keystore import KeyStore
from core.msfActionModule import MsfActionModule


class scan_msf_snmpenumusers(MsfActionModule):
    def __init__(self, config, display, lock):
        super(scan_msf_snmpenumusers, self).__init__(config, display, lock)
        self.triggers = ["snmpCred"]
        self.requirements = ["msfconsole"]
        self.title = "Enumerate Local User Accounts Using LanManager/psProcessUsername OID Values"
        self.shortName = "MSFSNMPEnumUsers"
        self.description = "execute [auxiliary/scanner/snmp/snmp_enumusers] on each target"
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

                    # Get list of working community strings for this host
                    comStrings = KeyStore.get(f"vuln/host/{t}/snmpCred/communityString")
                    for comString in comStrings:
                        cmd = {'config': ["use auxiliary/scanner/snmp/snmp_enumusers", f"set RHOSTS {t}",
                                          f"set COMMUNITY {comString}"], 'payload': 'none'}

                        result, outfile = self.execute_msf(t, cmd)

                        # Extract usernames from results and add to KeyStore
                        parts = re.findall(".* users: .*", result)
                        for part in parts:
                            userlist = (part.split(':')[2]).split(',')
                            for username in userlist:
                                KeyStore.add(f"creds/host/{t}/username/{username.strip()}")

        return
