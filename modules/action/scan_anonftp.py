import socket
from ftplib import FTP, error_perm

from core.actionModule import actionModule
from core.keystore import KeyStore
from core.utils import Utils


class scan_anonftp(actionModule):
    def __init__(self, config, display, lock):
        super(scan_anonftp, self).__init__(config, display, lock)
        self.title = "Test for Anonymous FTP"
        self.shortName = "anonymousFTP"
        self.description = "connect to remote FTP service as anonymous"

        self.requirements = []
        self.triggers = ["newService_ftp", "newPort_tcp_21"]

        self.safeLevel = 4

    def getTargets(self):
        # we are interested in all hosts that have ftp service
        self.targets = KeyStore.get('service/ftp')

    def testTarget(self, host, port):
        if self.seentarget(host + str(port)):
            return
        self.addseentarget(host + str(port))
        self.display.verbose(f"{self.shortName} - Connecting to {host}")
        cap = self.pktCap(filter_str=f"tcp and port {str(port)} and host {host}", packetcount=10, timeout=10,
                          srcip=self.config['lhost'], dstip=host)

        ftp = FTP()
        try:
            ftp.connect(host, int(port))
            outfile = self.config["proofsDir"] + self.shortName + "_PCAP_Port" + str(
                port) + "_" + host + "_" + Utils.getRandStr(10)

            try:
                result = ftp.login("anonymous", "anon@mo.us")
                if "Login successful" in result:
                    self.fire("anonymousFtp")
                    self.addVuln(host, "anonymousFTP", {"port": str(port), "output": outfile.replace("/", "%2F")})

                    self.display.error(f"VULN [AnonymousFTP] Found on [{host}]")
                else:
                    self.display.verbose(f"Could not login as anonymous to FTP at {host}")
            except error_perm as e:
                self.display.verbose(f"Could not login as anonymous to FTP at {host}. error: {e}")
            ftp.close()
            Utils.writeFile(self.getPktCap(cap), outfile)
        except EOFError as e:
            self.display.verbose(f"Could not find FTP server located at {host} Port {str(port)}. error: {e}")

        except socket.error as e:
            self.display.verbose(f"Could not find FTP server located at {host} Port {str(port)}. error: {e}")

    def process(self):
        self.getTargets()
        for t in self.targets:
            ports = KeyStore.get(f'service/ftp/{t}/tcp')
            for p in ports:
                self.testTarget(t, p)
        return
