try:
    import xml.etree.cElementTree as ElementTree
except ImportError:
    import xml.etree.ElementTree as ElementTree
from core.actionModule import actionModule
from core.keystore import KeyStore
from core.mynmap import MyNmap


class scan_nmap_vnc_auth_bypass(actionModule):
    def __init__(self, config, display, lock):
        super(scan_nmap_vnc_auth_bypass, self).__init__(config, display, lock)
        self.title = "NMap VNC Auth Bypass"
        self.shortName = "NmapVNCAuthBypass"
        self.description = "execute [nmap -p5800,5900 --script realvnc-auth-bypass] on each target"

        self.requirements = ["nmap"]
        self.triggers = ["newPort_tcp_5800", "newPort_tcp_5900"]

        self.safeLevel = 5

    def getTargets(self):
        self.targets = KeyStore.get('port/tcp/5800', 'port/tcp/5900')

    def myProcessPortScript(self, host, proto, port, script, outfile):
        outfile = f"{outfile}.xml"
        scriptid = script.attrib['id']
        if scriptid == "realvnc-auth-bypass":
            output = script.attrib['output']
            for elem in script.iter('elem'):
                if elem.attrib['key'] == "state" and elem.text == "VULNERABLE":
                    self.addVuln(host, "VNCNoAuth",
                                 {"message": "RealVNC 4.1.0 - 4.1.1 Authentication Bypass", "port": port})
                    self.fire("vncAccess")

    def process(self):
        self.getTargets()
        for t in self.targets:
            if not self.seentarget(t):
                self.addseentarget(t)
                self.display.verbose(f"{self.shortName} - Connecting to {t}")
                n = MyNmap(self.config, self.display, port_script_func=self.myProcessPortScript)

                scan_results = n.run(target=t, flags="--script realvnc-auth-bypass", ports="5800,5900",
                                     vector=self.vector, file_tag=f"{t}_VNCAUTHBYPASS")

        return
