import re

from core.keystore import KeyStore
from core.msfActionModule import MsfActionModule


class post_msf_gathersessioninfo(MsfActionModule):
    def __init__(self, config, display, lock):
        super(post_msf_gathersessioninfo, self).__init__(config, display, lock)
        self.title = "Get Info about any new sessions"
        self.shortName = "MSFGatherSessionInfo"
        self.description = "execute [getuid] and [sysinfo] on any new msf sessions"

        self.requirements = ["msfconsole"]
        self.triggers = ["msfSession"]

        self.safeLevel = 4

    def getTargets(self):
        # we are interested only in the hosts that had null sessions
        self.targets = KeyStore.get('shell/*/msf')

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        for t in self.targets:
            sessions = KeyStore.get(f'shell/{t}/msf')

            if len(sessions) > 0:
                # loop over each target
                for s in sessions:
                    # verify we have not tested this session before
                    if not self.seentarget(s):
                        # add the new IP to the already seen list
                        self.addseentarget(s)

                        cmd = {'config': [f"sessions -i {str(s)}", "SLEEP", "getuid", "SLEEP", "background", "SLEEP"],
                               'payload': 'none'}

                        result, outfile = self.execute_msf(t, cmd)

                        for line in result.splitlines():
                            if m := re.match(r'^\s*Server username: (.*)\s*', line):
                                self.display.verbose(f"Metasploit Session [{s}] running as user [{m[1].strip()}]")

                        cmd = {'config': [f"sessions -i {str(s)}", "SLEEP", "sysinfo", "SLEEP", "background", "SLEEP"],
                               'payload': 'none'}

                        result, outfile = self.execute_msf(t, cmd)

                        for line in result.splitlines():
                            if m := re.match(r'^\s*OS\s+: (.*)\s*', line):
                                self.display.verbose(f"Metasploit Session [{s}] running on OS [{m[1].strip()}]")

        return
