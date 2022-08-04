import re

from core.actionModule import actionModule
from core.keystore import KeyStore
from core.utils import Utils


class scan_testsslserver(actionModule):
    def __init__(self, config, display, lock):
        super(scan_testsslserver, self).__init__(config, display, lock)
        self.title = "Determine SSL protocols and ciphers"
        self.shortName = "SSLTestSSLServer"
        self.description = "execute [TestSSLServer <server> <port>] on each target"

        self.requirements = ["java"]
        self.triggers = ["newService_https", "newService_ssl", "newPort_tcp_443", "newPort_tcp_8443"]

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

                    command = ((((self.config["java"] + " -jar " + self.config[
                        "miscDir"]) + "TestSSLServer.jar ") + t) + " ") + port

                    result = Utils.execWait(command, temp_file, timeout=30)
                    depricatedlist = []
                    weakciphers = []
                    keystrength = ""
                    tls12 = False
                    with open(temp_file, "r") as myfile:
                        result = myfile.readlines()
                    for line in result:
                        if tls12:
                            if re.match('^ {4}(.*)', line):
                                cipher = line.strip()
                                if "DES" in cipher and cipher not in weakciphers or "DES" not in cipher and "RSA" in \
                                        cipher and cipher not in weakciphers or "DES" not in cipher and "RSA" not in \
                                        cipher and "NULL" in cipher and cipher not in weakciphers:
                                    weakciphers.append(cipher)
                            else:
                                tls12 = False
                        else:
                            m = re.match(r'^\s*Supported versions: (.*)', line)
                            if m:
                                if "SSLv2" in m[1]:
                                    protocol = "SSLv2"
                                    if protocol not in depricatedlist:
                                        depricatedlist.append(protocol)
                                elif "SSLv3" in m[1]:
                                    protocol = "SSLv3"
                                    if protocol not in depricatedlist:
                                        depricatedlist.append(protocol)
                                elif "TLSv1.0" in m[1]:
                                    protocol = "TLSv1.0"
                                    if protocol not in depricatedlist:
                                        depricatedlist.append(protocol)
                                elif "TLSv1.1" in m[1]:
                                    protocol = "TLSv1.1"
                                    if protocol not in depricatedlist:
                                        depricatedlist.append(protocol)
                            m = re.match(r'^ {2}TLSv1.2\s*', line)
                            if m:
                                tls12 = True
                    for depricatedProto in depricatedlist:
                        KeyStore.add(f'service/https/{t}/tcp/{port}/depricatedSSLProto/{depricatedProto}')

                    for weakCipher in weakciphers:
                        KeyStore.add(f'service/https/{t}/tcp/{port}/weakSSLCipher/{weakCipher}')

                    if keystrength != "":
                        KeyStore.add(f'service/https/{t}/tcp/{port}/weakSSLKeyStrength/{keystrength}')

        return
