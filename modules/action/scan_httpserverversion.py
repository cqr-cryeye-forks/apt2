import http.client

from core.actionModule import actionModule
from core.keystore import KeyStore
from core.utils import Utils


class scan_httpserverversion(actionModule):
    def __init__(self, config, display, lock):
        super(scan_httpserverversion, self).__init__(config, display, lock)
        self.title = "Get HTTP Server Version"
        self.shortName = "HTTPServerVersion"
        self.description = "issue [GET / HTTP/1.0] to each web server"

        self.requirements = []
        self.triggers = ["newService_http", "newService_https", "newPort_tcp_80", "newPort_tcp_443"]
        self.types = ["http"]

        self.safeLevel = 5

    def getTargets(self):
        # we are interested in all hosts
        self.targets = KeyStore.get('service/http', 'service/https')

    def processTarget(self, t, port):
        if self.seentarget(t + str(port)):
            return
        self.addseentarget(t + str(port))
        self.display.verbose(f"{self.shortName} - Connecting to {t}")
        try:
            conn = http.client.HTTPConnection(t, port, timeout=10)
            conn.request('GET', '/')
            response = conn.getresponse()
            if serverver := response.getheader('server'):
                outfile = ((self.config["proofsDir"] + self.shortName + "_" + t + "_" + str(port)) + "_") + Utils.getRandStr(10)

                Utils.writeFile(("Identified Server Version of %s : %s\n\nFull Headers:\n%s" % (t, serverver, self.print_dict(response.getheaders()))), outfile)

                KeyStore.add(f"host/{t}/files/{self.shortName}/" + outfile.replace("/", "%2F"))
        except http.client.BadStatusLine:
            pass
        except:
            pass

    def process(self):
        self.getTargets()
        for t in self.targets:
            ports = KeyStore.get(f'service/http{t}/tcp', f'service/https/{t}/tcp')
            for port in ports:
                self.processTarget(t, port)
                for hostname in self.getHostnames(t):
                    self.processTarget(hostname, port)
        return
