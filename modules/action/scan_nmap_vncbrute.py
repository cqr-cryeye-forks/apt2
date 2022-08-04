try:
    import xml.etree.cElementTree as ElementTree
except ImportError:
    import xml.etree.ElementTree as ElementTree
from core.actionModule import actionModule
from core.keystore import KeyStore
from core.mynmap import MyNmap


class scan_nmap_vncbrute(actionModule):
    def __init__(self, config, display, lock):
        super(scan_nmap_vncbrute, self).__init__(config, display, lock)
        self.title = "NMap VNC Brute Scan"
        self.shortName = "NmapVNCBruteScan"
        self.description = "execute [nmap -p5800,5900 --script vnc-brute] on each target"

        self.requirements = ["nmap"]
        self.triggers = ["newPort_tcp_5800", "newPort_tcp_5900"]

        self.safeLevel = 5

    def getTargets(self):
        self.targets = KeyStore.get('port/tcp/5800', 'port/tcp/5900')

    def myProcessPortScript(self, host, proto, port, script, outfile):
        scriptid = script.attrib['id']
        if scriptid == "vnc-brute":
            outfile = f"{outfile}.xml"
            output = script.attrib['output']
            if "No authentication required" in output:
                self.addVuln(host, "VNCNoAuth", {"port": port, "message": "No authentication required",
                                                 "output": outfile.replace("/", "%2F")})
                self.fire("VNCNoAuth")
            for elem in script.iter('elem'):
                if elem.attrib['key'] == "password":
                    self.addVuln(host, "VNCBrutePass", {"port": port, "password": elem.text})
                    self.fire("VNCBrutePass")

    def process(self):
        self.getTargets()
        for t in self.targets:
            if not self.seentarget(t):
                self.addseentarget(t)
                self.display.verbose(f"{self.shortName} - Connecting to {t}")
                n = MyNmap(self.config, self.display, port_script_func=self.myProcessPortScript)

                scan_results = n.run(target=t, flags="--script vnc-brute", ports="5800,5900", vector=self.vector,
                                     file_tag=f"{t}_VNCBRUTE")

        return
