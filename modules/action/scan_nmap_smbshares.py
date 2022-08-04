try:
    import xml.etree.cElementTree as ElementTree
except ImportError:
    import xml.etree.ElementTree as ElementTree
from core.actionModule import actionModule
from core.keystore import KeyStore
from core.mynmap import MyNmap


class scan_nmap_smbshares(actionModule):
    def __init__(self, config, display, lock):
        super(scan_nmap_smbshares, self).__init__(config, display, lock)
        self.title = "NMap SMB Share Scan"
        self.shortName = "NmapSMBShareScan"
        self.description = "execute [nmap -p445 --script smb-enum-shares] on each target"

        self.requirements = ["nmap"]
        self.triggers = ["newPort_tcp_445", "newPort_tcp_139"]

        self.safeLevel = 5

    def getTargets(self):
        self.targets = KeyStore.get('port/tcp/139', 'port/tcp/445')

    def myProcessHostScript(self, host, script, outfile):
        scriptid = script.attrib['id']
        if scriptid == "smb-enum-shares":
            outfile = f"{outfile}.xml"
            output = script.attrib['output']
            files = {}
            for volumes in script.findall("table"):
                readAccess = False
                writeAccess = False
                for volume in volumes:
                    sharename = ""
                    sharetype = ""
                    sharecomment = ""
                    anonaccess = ""
                    useraccess = ""

                    sharename = volume.attrib["key"]
                    for elem in volume:
                        if elem.attrib["key"] == "Type":
                            sharetype = elem.text.replace("/", "%2F")
                        if elem.attrib["key"] == "Comment":
                            sharecomment = elem.text.replace("/", "%2F")
                        elif elem.attrib["key"] == "Anonymous access":
                            rights = elem[0].text
                            if "READ" in rights:
                                readAccess = True
                            if "WRITE" in rights:
                                writeAccess = True
                            anonaccess = rights.replace("/", "%2F")
                        elif elem.attrib["key"] == "Current user access":
                            rights = elem[0].text
                            if "READ" in rights:
                                readAccess = True
                            if "WRITE" in rights:
                                writeAccess = True
                            useraccess = rights.replace("/", "%2F")
                    KeyStore.add(f"share/smb/{sharename}/{host}/" + str(f"Info: {anonaccess}"))

                if readAccess:
                    self.addVuln(host, "smb-read", {"port": "445", "output": outfile.replace("/", "%2F")})
                    self.fire("nfsRead")
                if writeAccess:
                    self.addVuln(host, "smb-write", {"port": "445", "output": outfile.replace("/", "%2F")})
                    self.fire("nfsWrite")

    def process(self):
        self.getTargets()
        for t in self.targets:
            if not self.seentarget(t):
                self.addseentarget(t)
                self.display.verbose(f"{self.shortName} - Connecting to {t}")
                n = MyNmap(self.config, self.display, host_script_func=self.myProcessHostScript)

                scan_results = n.run(target=t, flags="--script smb-enum-shares", ports="445", vector=self.vector,
                                     file_tag=f"{t}_SMBSHARESCAN")

        return
