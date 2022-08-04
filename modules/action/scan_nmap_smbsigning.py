try:
    import xml.etree.cElementTree as ElementTree
except ImportError:
    import xml.etree.ElementTree as ElementTree
from core.actionModule import actionModule
from core.keystore import KeyStore
from core.mynmap import MyNmap


class scan_nmap_smbsigning(actionModule):
    def __init__(self, config, display, lock):
        super(scan_nmap_smbsigning, self).__init__(config, display, lock)
        self.title = "NMap SMB-Signing Scan"
        self.shortName = "NmapSMBSigning"
        self.description = "execute [nmap -p445 --script smb-security-mode] on each target"

        self.requirements = ["nmap"]
        self.triggers = ["newPort_tcp_445", "newPort_tcp_139"]

        self.safeLevel = 5

    def getTargets(self):
        self.targets = KeyStore.get('port/tcp/139', 'port/tcp/445')

    def myProcessHostScript(self, host, script, outfile):
        scriptid = script.attrib['id']
        if scriptid == "smb-security-mode":
            outfile = f"{outfile}.xml"
            output = script.attrib['output']
            self._extracted_from_myProcessHostScript_6(script, host, outfile)

    # TODO Rename this here and in `myProcessHostScript`
    def _extracted_from_myProcessHostScript_6(self, script, host, outfile):
        account_used = ""
        authentication_level = ""
        challenge_response = ""
        message_signing = ""
        for elem in script.findall("elem"):
            if elem.attrib["key"] == "account_used":
                account_used = elem.text
            elif elem.attrib["key"] == "authentication_level":
                authentication_level = elem.text
            elif elem.attrib["key"] == "challenge_response":
                challenge_response = elem.text
            elif elem.attrib["key"] == "message_signing":
                message_signing = elem.text
        if "disabled" in message_signing:
            self.addVuln(host, "SMBSigningDisabled", {"port": "445", "output": outfile, "Account Used": account_used,
                                                      "Authentication Level": authentication_level,
                                                      "Challenge Response": challenge_response,
                                                      "Message Signing": message_signing})

            self.fire("SMBSigningDisabled")

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        # loop over each target
        for t in self.targets:
            # verify we have not tested this host before
            if not self.seentarget(t):
                # add the new IP to the already seen list
                self.addseentarget(t)
                # run nmap
                n = MyNmap(self.config, self.display, host_script_func=self.myProcessHostScript)
                scan_results = n.run(target=t, flags="--script smb-security-mode", ports="445", vector=self.vector,
                                     file_tag=f"{t}_SMBSIGNINGSCAN")

        return
