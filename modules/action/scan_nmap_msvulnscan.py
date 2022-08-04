from core.actionModule import actionModule
from core.keystore import KeyStore
from core.mynmap import MyNmap


class scan_nmap_msvulnscan(actionModule):
    def __init__(self, config, display, lock):
        super(scan_nmap_msvulnscan, self).__init__(config, display, lock)
        self.title = "Nmap MS Vuln Scan"
        self.shortName = "NmapVulnScan"
        self.description = "execute [nmap --script vuln -p445] on each target"

        self.requirements = ["nmap"]
        self.triggers = ["newPort_tcp_445", "newPort_tcp_139"]

        self.safeLevel = 4

    def getTargets(self):
        self.targets = KeyStore.get('port/tcp/139', 'port/tcp/445')

    def myProcessHostScript(self, host, script, outfile):
        outfile = f"{outfile}.xml"
        scriptid = script.attrib['id']
        output = script.attrib['output']
        if scriptid.startswith("smb-vuln-"):
            for table in script.findall('table'):
                for elem in table.findall('elem'):
                    if elem.attrib['key'] == "state" and ("VULNERABLE" in elem.text or "INFECTED" in elem.text):
                        shortid = scriptid[9:]
                        self.addVuln(host, shortid, {"port": "445", "output": outfile.replace("/", "%2F")})

                        self.fire(shortid)

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        # loop over each target
        for t in self.targets:
            # verify we have not tested this host before
            if not self.seentarget(t):
                # add the new IP to the already seen lisT
                self.addseentarget(t)
                self.display.verbose(f"{self.shortName} - Connecting to {t}")
                # run nmap
                n = MyNmap(self.config, self.display, host_script_func=self.myProcessHostScript)
                scan_results = n.run(target=t, flags="--script vuln", ports="445", vector=self.vector,
                                     file_tag=f"{t}_MSVULNSCAN")

        return
