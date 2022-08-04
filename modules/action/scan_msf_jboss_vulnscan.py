import re

from core.keystore import KeyStore
from core.msfActionModule import MsfActionModule


class scan_msf_jboss_vulnscan(MsfActionModule):
    def __init__(self, config, display, lock):
        super(scan_msf_jboss_vulnscan, self).__init__(config, display, lock)
        self.triggers = ["newService_http", "newPort_tcp_80", "newPort_tcp_8080"]
        self.requirements = ["msfconsole"]
        self.types = ["http"]
        self.title = "Attempt to determine if a jboss instance has default creds"
        self.shortName = "MSFJbossVulnscan"
        self.description = "execute [auxiliary/scanner/http/jboss_vulnscan] on each target"
        self.safeLevel = 4

    def getTargets(self):
        self.targets = KeyStore.get('port/tcp/443', 'port/tcp/8443', 'service/https', 'service/ssl')

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        if len(self.targets) > 0:
            # loop over each target
            for t in self.targets:
                ports = KeyStore.get(f'service/http/{t}/tcp')
                for p in ports:
                    # verify we have not tested this host before
                    if not self.seentarget(t + p):
                        # add the new IP to the already seen list
                        self.addseentarget(t + p)

                        cmd = {'config': ["use auxiliary/scanner/http/jboss_vulnscan", f"set RHOSTS {t}",
                                          f"set RPORT {p}"], 'payload': 'none'}

                        result, outfile = self.execute_msf(t, cmd)

                        for line in result.splitlines():
                            if m := re.match(r'.*Authenticated using (.*):(.*)', line):
                                self.display.error(
                                    f"Jboss on [{t}:{p}] has default creds of [{m[1].strip()}]/[{m[2].strip()}]")

                                KeyStore.add(
                                    f"creds/service/jboss/{t}/port/{p}/username/{m[1].strip()}/password/{m[2].strip()}")

                                self.fire("newJbossPassword")

        return
