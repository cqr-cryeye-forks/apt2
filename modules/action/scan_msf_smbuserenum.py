import re

from core.keystore import KeyStore
from core.msfActionModule import MsfActionModule
from core.utils import Utils


class scan_msf_smbuserenum(MsfActionModule):
    def __init__(self, config, display, lock):
        super(scan_msf_smbuserenum, self).__init__(config, display, lock)
        self.title = "Get List of Users From SMB"
        self.shortName = "MSFSMBUserEnum"
        self.description = "execute [auxiliary/scanner/smb/smb_enumusers] on each target"

        self.requirements = ["msfconsole"]
        self.triggers = ["nullSession"]

        self.safeLevel = 5

    def getTargets(self):
        # we are interested only in the hosts that had null sessions
        self.targets = KeyStore.get('vuln/host/*/nullSession')

    def process(self):
        self.getTargets()
        if len(self.targets) > 0:
            for t in self.targets:
                if not self.seentarget(t):
                    self.addseentarget(t)
                    cmd = {'config': ["use auxiliary/scanner/smb/smb_enumusers", f"set RHOSTS {t}"], 'payload': 'none'}

                    result, outfile = self.execute_msf(t, cmd)
                    parts = re.findall(".*" + t.replace(".", "\.") + ".*", result)
                    for part in parts:
                        if "RHOSTS" not in part:
                            try:
                                pieces = part.split()
                                domain = pieces[3]
                                KeyStore.add(f"host/{t}/domain/{domain.strip()}")
                                extras = part.split('(')[1].split(')')[0]
                                users = part.split('[')[3].split(']')[0].split(',')
                                for user in users:
                                    KeyStore.add(f"creds/host/{t}/username/{user.strip()}")
                            except Exception as e:
                                print(e)
                    outfile = self.config["proofsDir"] + self.shortName + "_" + t + "_" + Utils.getRandStr(10)

                    Utils.writeFile(result, outfile)
                    KeyStore.add(f"host/{t}/files/{self.shortName}/" + outfile.replace("/", "%2F"))
        return
