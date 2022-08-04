from core.actionModule import actionModule
from core.keystore import KeyStore
from core.utils import Utils


class scan_httpscreenshot(actionModule):
    def __init__(self, config, display, lock):
        super(scan_httpscreenshot, self).__init__(config, display, lock)
        self.title = "Get Screen Shot of Web Pages"
        self.shortName = "httpScreenShot"
        self.description = "load each web server and get a screenshot"

        self.requirements = ["phantomjs"]
        self.triggers = ["newService_http", "newService_https", "newPort_tcp_80", "newPort_tcp_443"]
        self.types = ["http"]

        self.safeLevel = 5

    def getTargets(self):
        # we are interested in all hosts
        self.targets = KeyStore.get('service/http', 'service/https')

    def processTarget(self, t, port):
        if not self.seentarget(t + str(port)):
            self.addseentarget(t + str(port))
            self.display.verbose(f"{self.shortName} - Connecting to {t}")
            outfile = self.config["proofsDir"] + self.shortName + "_" + t + "_" + str(port) + "_" + Utils.getRandStr(
                10) + ".png"
            url = f"http://{t}:{str(port)}"
            Utils.webScreenCap(url, outfile)

    def process(self):
        self.getTargets()
        for t in self.targets:
            ports = KeyStore.get(f'service/http/{t}/tcp', f'service/https/{t}/tcp')
            for port in ports:
                self.processTarget(t, port)
                for hostname in self.getHostnames(t):
                    self.processTarget(hostname, port)
        return
