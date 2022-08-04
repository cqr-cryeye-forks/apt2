import http.client

from core.actionModule import actionModule
from core.keystore import KeyStore
from core.utils import Utils


class scan_httpoptions(actionModule):
    def __init__(self, config, display, lock):
        super(scan_httpoptions, self).__init__(config, display, lock)
        self.title = "Get HTTP Options"
        self.shortName = "httpOptions"
        self.description = "issue [OPTIONS / HTTP/1.0] to each web server"

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
            self._extracted_from_processTarget_6(t, port)
        except http.client.BadStatusLine:
            pass
        except Exception:
            pass

    # TODO Rename this here and in `processTarget`
    def _extracted_from_processTarget_6(self, t, port):
        conn = http.client.HTTPConnection(t, port, timeout=10)
        conn.request('OPTIONS', '/')
        response = conn.getresponse()
        text = ""
        allowed = response.getheader('allow')
        outfile = self.config["proofsDir"] + self.shortName + "_" + t + "_" + str(port) + "_" + Utils.getRandStr(10)

        if allowed:
            badoptions = ['PUT', 'DELETE', 'TRACE', 'TRACK']
            for badopt in badoptions:
                if 'badopt' in allowed:
                    self.fire(f"httpOption{badopt}")
                    self.addVuln(t, f"httpOption{badopt}", {"port": str(port), "output": outfile.replace("/", "%2F")})
                    self.display.error("VULN [httpOption%s] Found on [%s:%i]" % (badopt, t, int(port)))

            text = "Allowed HTTP Options for %s : %s\n\nFull Headers:\n%s" % (
                t, allowed, self.print_dict(response.getheaders()))

        else:
            text = "Allowed HTTP Options for %s : OPTIONS VERB NOT ALLOWED\n\nFull Headers:\n%s" % (
                t, self.print_dict(response.getheaders()))

        Utils.writeFile(text, outfile)

    def process(self):
        self.getTargets()
        for t in self.targets:
            ports = KeyStore.get(f'service/http/{t}/tcp', f'service/https/{t}/tcp')
            for port in ports:
                self.processTarget(t, port)
                for hostname in self.getHostnames(t):
                    self.processTarget(hostname, port)
        return
