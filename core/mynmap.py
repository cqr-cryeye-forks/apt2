try:
    import xml.etree.cElementTree as ElementTree
except ImportError:
    import xml.etree.ElementTree as ElementTree
from core.events import EventHandler
from core.keystore import KeyStore
from core.utils import Utils


class MyNmap:
    def __init__(self, config, display, host_script_func=None, port_script_func=None):
        self.config = config
        self.display = display
        if not config:
            self.config = {}

        self.host_script_func = host_script_func
        if not host_script_func:
            self.host_script_func = self.processHostScript
        self.port_script_func = port_script_func
        if not port_script_func:
            self.port_script_func = self.processScript

        self.outfile = ""
        self.vector = ""

    def run(self, target="127.0.0.1", ports="1-1024", flags="-sS", vector="", file_tag=""):
        proofsDir = ""
        if "proofsDir" in list(self.config.keys()):
            proofsDir = self.config["proofsDir"]
        file_tag = file_tag.replace("/", "_").replace(" ", "_")
        self.outfile = f"{proofsDir}NMAP-{file_tag}-{Utils.getRandStr(10)}"
        command = f"nmap {flags} -p {ports} -oA {self.outfile} {target}"

        tmp_results = Utils.execWait(command)
        self.display.output(f"Scan file saved to [{self.outfile}]")
        return self.loadXMLFile(f"{self.outfile}.xml")

    def loadXMLFile(self, file, vector=""):
        self.vector = vector
        tree = ElementTree.parse(file)
        self.processXML(tree)
        return tree.getroot()

    def getOutfile(self):
        return self.outfile

    def processXML(self, tree):
        for host in tree.iter('host'):
            if host.find('status').attrib['state'] == 'up':
                host_ip = self.processHost(host)
                if host.find('os'):
                    self.processOs(host_ip, host.find('os'))
                for host_script in host.findall('host_script'):
                    for script in host_script.findall('script'):
                        self.host_script_func(host_ip, script, self.outfile)
                if host.find('ports'):
                    for port in host.find('ports').findall('port'):
                        self.processPort(host_ip, port)

    def processHost(self, host):
        ip = ""
        for addr in host.findall('address'):
            ip_tmp = addr.attrib['addr']
            addrType = addr.attrib['addrtype']
            if addrType == "ipv4":
                ip = ip_tmp
                KeyStore.add(f'host/{ip}')
                EventHandler.fire(f"newIP:{self.vector}")
        if host.find('hostname'):
            for hostname in host.find('hostnames').findall('hostname'):
                name = hostname.attrib['name']
                KeyStore.add(f'host/{ip}/dns/{name}')
        return ip

    @staticmethod
    def processOs(host, os):
        osStrAcc = 0
        for osmatch in os.findall('osmatch'):
            osStrAcc_tmp = osmatch.attrib['accuracy'] or ""
            if int(osStrAcc_tmp) > osStrAcc:
                osStrAcc = int(osStrAcc_tmp)
        osFam = ""
        osGen = ""
        osClassAcc = 0
        for osclass in os.findall('osclass'):
            osFam_tmp = osclass.attrib['osfamily'] or ""
            osGen_tmp = osclass.attrib['osgen'] or ""
            osClassAcc_tmp = osclass.attrib['accuracy'] or ""
            if int(osClassAcc_tmp) > osClassAcc:
                osClassAcc = int(osClassAcc_tmp)
                osFam = osFam_tmp
                osGen = osGen_tmp
        KeyStore.add(f'host/{host}/os/{osFam} {osGen}')

    def processPort(self, host, port):
        state = port.find('state').attrib['state']
        if state == "open":
            port_num = port.attrib['portid']
            proto = port.attrib['protocol']
            KeyStore.add(f'port/{proto}/{port_num}/{host}')
            EventHandler.fire(f"newPort_{proto}_{port_num}:{self.vector}")
            self.processService(host, port_num, proto, port.find('service'))
            for script in port.findall('script'):
                self.port_script_func(host, port_num, proto, script, self.outfile)

    def processService(self, host, port, proto, service):
        name = ""
        product = ""
        version = ""
        for key, value in list(service.attrib.items()):
            if key == 'name':
                name = value
                if "http" in name:
                    name = "https" if "https" in name or "ssl" in name else "http"
            elif key == 'product':
                product = value
            elif key == 'version':
                version = value
        KeyStore.add(f'service/{name}/{host}/{proto}/{port}/version/{product} {version}')

        EventHandler.fire(f"newService_{name}:{self.vector}")

    def processHostScript(self, host, script, outfile):
        #        print script.attrib['id']
        #        print script.attrib['output']
        #        for child in script:
        #            print child.tag
        #            print child.text
        #            print child.attrib
        return

    def processScript(self, host, port, proto, script, outfile):
        #        print script.attrib['id']
        #        print script.attrib['output']
        #        for child in script:
        #            print child.tag
        #            print child.text
        #            print child.attrib
        return
