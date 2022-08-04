import re

from core.actionModule import actionModule
from core.keystore import KeyStore
from core.utils import Utils


class scan_sslscan(actionModule):
    def __init__(self, config, display, lock):
        super(scan_sslscan, self).__init__(config, display, lock)
        self.title = "Determine SSL protocols and ciphers"
        self.shortName = "SSLTestSSLScan"
        self.description = "execute [sslscan <server>:<port> on each target"

        self.requirements = ["sslscan"]
        self.triggers = ["newService_ssl", "newService_https", "newPort_tcp_443", "newPort_tcp_8443"]

        self.safeLevel = 5

    def getTargets(self):
        self.targets = KeyStore.get('service/https', 'service/ssl')

    def process(self):
        self.getTargets()
        for t in self.targets:
            ports = KeyStore.get(f'service/https/{t}/tcp', f'service/ssl/{t}/tcp')
            for port in ports:
                if not self.seentarget(t + str(port)):
                    self.addseentarget(t + str(port))
                    temp_file = ((self.config["proofsDir"] + self.shortName + "_" + t + "_" + str(
                        port)) + "_") + Utils.getRandStr(10)

                    command = self.config["sslscan"] + " --no-color " + t + ":" + port
                    result = Utils.execWait(command, temp_file, timeout=60)
                    depricatedlist = []
                    weakciphers = []
                    keystrength = ""
                    with open(temp_file, "r") as myfile:
                        result = myfile.readlines()
                    for line in result:
                        if m := re.match(r'^\s*Accepted\s\s+([^ ]*)\s+(\d+)\s\s+ts\s*([^ ]*)', line):
                            protocol = m[1].strip()
                            bit = m[2].strip()
                            cipher = m[3].strip()
                            if protocol in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]:
                                if protocol not in depricatedlist:
                                    depricatedlist.append(protocol)
                            elif protocol == "TLSv1.2":
                                if "DES" in cipher and cipher not in weakciphers \
                                        or "DES" not in cipher and "RSA" in cipher and cipher not in weakciphers \
                                        or "DES" not in cipher and "RSA" not in cipher and "NULL" in cipher \
                                        and cipher not in weakciphers or "DES" not in cipher and "RSA" \
                                        not in cipher and "NULL" not in cipher and int(bit) < 112 \
                                        and cipher not in weakciphers:
                                    weakciphers.append(cipher)
                        elif m := re.match(r'^\s*RSA Key Strength:\s*(\d+)', line):
                            if int(m[1].strip()) < 2048:
                                keystrength = m[1].strip()
                    for depricatedProto in depricatedlist:
                        KeyStore.add(f'service/https/{t}/tcp/{port}/depricatedSSLProto/{depricatedProto}')

                    for weakCipher in weakciphers:
                        KeyStore.add(f'service/https/{t}/tcp/{port}/weakSSLCipher/{weakCipher}')
                    if keystrength != "":
                        KeyStore.add(f'service/https/{t}/tcp/{port}/weakSSLKeyStrength/{keystrength}')
                    self.display.debug((((f"{t},{str(port)}," + ' '.join(depricatedlist) + "," + ' '.join(
                        weakciphers)) + ",") + keystrength))

        return
