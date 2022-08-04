from core.actionModule import actionModule
from core.keystore import KeyStore
from core.mynmap import MyNmap


class scan_nmap_sslscan(actionModule):
    def __init__(self, config, display, lock):
        super(scan_nmap_sslscan, self).__init__(config, display, lock)
        self.title = "NMap SSL Scan"
        self.shortName = "NmapSSLScan"
        self.description = "execute [nmap --script ssl-ccs-injection,ssl-cert,ssl-date,ssl-dh-params," \
                           "ssl-enum-ciphers,ssl-google-cert-catalog,ssl-heartbleed,ssl-known-key,ssl-poodle," \
                           "sslv2] on each target"

        self.requirements = ["nmap"]
        self.triggers = ["newService_ssl", "newService_https", "newPort_tcp_443", "newPort_tcp_8443"]

        self.safeLevel = 5

    def getTargets(self):
        self.targets = KeyStore.get('port/tcp/443', 'port/tcp/8443', 'service/https', 'service/ssl')

    def process(self):
        self.getTargets()
        for t in self.targets:
            ports = KeyStore.get(f'service/https/{t}', f'service/ssl/host/{t}')
            for port in ports:
                if not self.seentarget(t + str(port)):
                    self.addseentarget(t + str(port))
                    n = MyNmap(self.config, self.display)
                    scan_results = n.run(target=t, flags="--script ssl-ccs-injection,ssl-cert,ssl-date,ssl-d"
                                                         "h-params,ssl-enum-ciphers,ssl-google-cert-catalog,ssl-h"
                                                         "eartbleed,ssl-known-key,ssl-poodle,sslv2",
                                         ports=str(port), vector=self.vector, file_tag=f"{t}_{str(port)}_SSLSCAN")

        return
