try:
    import xml.etree.cElementTree as ElementTree
except ImportError:
    import xml.etree.ElementTree as ElementTree
from core.actionModule import actionModule
from core.keystore import KeyStore
from core.mynmap import MyNmap


class scan_nmap_nfsshares(actionModule):
    def __init__(self, config, display, lock):
        super(scan_nmap_nfsshares, self).__init__(config, display, lock)
        self.title = "NMap NFS Share Scan"
        self.shortName = "NmapNFSShareScan"
        self.description = "execute [nmap -p111 --script nfs-ls,nfs-showmount] on each target"

        self.requirements = ["nmap"]
        self.triggers = ["newPort_udp_111", "newPort_tcp_111"]

        self.safeLevel = 5

    def getTargets(self):
        self.targets = KeyStore.get('port/tcp/111', 'port/udp/111')

    def myProcessPortScript(self, host, proto, port, script, outfile):
        outfile = f"{outfile}.xml"
        scriptid = script.attrib['id']
        output = script.attrib['output']
        if (scriptid == "nfs-ls"):
            readAccess = False
            writeAccess = False
            for volumes in script.findall("table"):
                for volume in volumes.findall("table"):
                    sharename = ""
                    shareinfo = ""
                    files = {}
                    for elem in volume:
                        if elem.attrib["key"] == "volume":
                            sharename = elem.text.replace("/", "%2F")
                        if elem.attrib["key"] == "info":
                            rights = elem[0].text
                            if "Read" in rights:
                                readAccess = True
                            if "Modify" in rights:
                                writeAccess = True
                            shareinfo = rights.replace("/", "%2F")
                        if elem.attrib["key"] == "files":
                            for file in elem:
                                newfile = {fileprop.attrib["key"]: fileprop.text for fileprop in file}
                                files[newfile["filename"]] = newfile
                    KeyStore.add(f"share/nfs/{host}/{sharename}/" + str(f"Info: {shareinfo}"))
            #                    for file in files:
            #                        # TODO - Maybe revisit adding more file properties here in addition to names
            #                        KeyStore.add("host/" + host + "/shares/NFS/" + sharename + "/Files/" + str(file).replace("/", "%2F"))
            #                        print ("host/" + host + "/shares/NFS/" + sharename + "/Files/" + str(file).replace("/", "%2F"))

            if readAccess:
                self.addVuln(host, "nfs-read", {"port": "111", "output": outfile.replace("/", "%2F")})
                self.fire("nfsRead")
            if writeAccess:
                self.addVuln(host, "nfs-write", {"port": "111", "output": outfile.replace("/", "%2F")})
                self.fire("nfsWrite")

    def process(self):
        self.getTargets()
        for t in self.targets:
            if not self.seentarget(t):
                self.addseentarget(t)
                self.display.verbose(f"{self.shortName} - Connecting to {t}")
                n = MyNmap(self.config, self.display, port_script_func=self.myProcessPortScript)

                scan_results = n.run(target=t, flags="--script nfs-ls,nfs-showmount", ports="111", vector=self.vector,
                                     file_tag=f"{t}_NFSSHARESCAN")

        return
