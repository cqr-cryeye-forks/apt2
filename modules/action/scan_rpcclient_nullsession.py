import re

from core.actionModule import actionModule
from core.keystore import KeyStore
from core.utils import Utils


class scan_rpcclient_nullsession(actionModule):
    def __init__(self, config, display, lock):
        super(scan_rpcclient_nullsession, self).__init__(config, display, lock)
        self.title = "Test for NULL Session"
        self.shortName = "NULLSessionRpcClient"
        self.description = "execute [rpcclient -U \"\" -N <IP> -c srvinfo] on each target"

        self.requirements = ["rpcclient"]
        self.triggers = ["newPort_tcp_445", "newPort_tcp_139"]

        self.safeLevel = 5

    def getTargets(self):
        # we are interested in all hosts
        self.targets = KeyStore.get('port/tcp/139', 'port/tcp/445')

    def process(self):
        self.getTargets()
        for t in self.targets:
            if not self.seentarget(t):
                self.addseentarget(t)
                self.display.verbose(f"{self.shortName} - Connecting to {t}")
                temp_file2 = self.config["proofsDir"] + "nmblookup_" + t + "_" + Utils.getRandStr(10)

                command2 = self.config["nmblookup"] + " -A " + t
                result2 = Utils.execWait(command2, temp_file2)
                workgroup = "WORKGROUP"
                for line in result2.split('\n'):
                    if m := re.match(r'\s+(.*)\s+<00> - <GROUP>.*', line):
                        workgroup = m[1].strip()
                        self.display.debug(f"found ip [{t}] is on the workgroup/domain [{workgroup}]")

                outfile = self.config["proofsDir"] + self.shortName + "_" + t + "_" + Utils.getRandStr(10)

                command = self.config["rpcclient"] + ' -N -U \"\" -W ' + workgroup + " " + t + " -c srvinfo"

                result = Utils.execWait(command, outfile)
                if any(x in result for x in ["NT_STATUS_LOGON_FAILURE", "NT_STATUS_ACCESS_DENIED"]):
                    self.display.verbose(f"Could not get NULL Session on {t}")
                else:
                    self.fire("nullSession")
                    self.addVuln(t, "nullSession", {"type": "rpc", "output": outfile.replace("/", "%2F")})

                    self.display.error(f"VULN [NULLSession] Found on [{t}]")
        return
