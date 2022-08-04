import contextlib
import re
from io import StringIO

try:
    from smb.SMBConnection import SMBConnection
except ImportError as e:
    raise ImportError('Missing pysmb library. To install run: pip install pysmb') from e


from core.actionModule import actionModule
from core.keystore import KeyStore
from core.utils import Utils


class scan_searchsmbshare(actionModule):
    def __init__(self, config, display, lock):
        super(scan_searchsmbshare, self).__init__(config, display, lock)
        self.title = "Search files on SMB Shares"
        self.shortName = "searchSMB"
        self.description = "connect to remote SMB Share service and search for interesting files"

        self.requirements = []
        self.triggers = ["newService_smb", "newPort_tcp_445", "newPort_tcp_139"]
        self.types = ["filesearch"]

        self.safeLevel = 4

        self.filepatterns = self.config["file_search_patterns"].split(",")

    def getTargets(self):
        # we are interested in all hosts
        self.targets = KeyStore.get('port/tcp/445', 'port/tcp/139')
        self.targets2 = KeyStore.get('service/smb')

    def searchDir(self, host, conn, share, path, depth=0):
        if depth > 5:
            return

        try:
            # list the files on each share (recursivity?)
            names = conn.listPath(share, path, timeout=30)

            for name in names:
                if name.isDirectory:
                    if name.filename not in ['.', '..']:
                        self.searchDir(conn, host, share, path + name.filename + '/', depth + 1)
                else:
                    for pattern in self.filepatterns:
                        with contextlib.suppress(re.error):
                            re.compile(pattern)
                            if result := re.match(pattern, name.filename):
                                # download the file
                                outfile = self.config[
                                              "proofsDir"] + self.shortName + "_" + host + "_" + share + "_" + name.filename.replace(
                                    "/", "-") + "_" + Utils.getRandStr(10)
                                temp_fh = StringIO()
                                conn.retrieveFile(share, path + name.filename, temp_fh)
                                temp_fh.seek(0)
                                Utils.writeFile(temp_fh.getvalue(), outfile)
                                self.display.debug(f"_____    Share[{share}] ={path}{name.filename}")
        except:
            self.display.debug('### can not access the resource')

        return

    def searchTarget(self, host, username, password, domainname):
        success = False
        try:
            self.display.debug(f'### Analyzing system: {host}')
            conn = SMBConnection(username, password, 'enumerator', host, domainname, use_ntlm_v2=True,
                                 sign_options=SMBConnection.SIGN_WHEN_SUPPORTED, is_direct_tcp=True)

            if connected := conn.connect(host, 445):
                success = True
                try:
                    Response = conn.listShares(timeout=30)
                    self.display.debug(f'Shares on: {host}')
                    for i in range(len(Response)):
                        self.display.debug(f"  Share[{str(i)}] ={str(Response[i].name)}")
                        self.searchDir(host, conn, Response[i].name, '/')
                except Exception:
                    self.display.debug('### can not list shares')
        except:
            self.display.debug(f'### can not access the system ({host}) ({username}) ({password}) ({domainname})')

        return success

    def process(self):
        self.getTargets()
        for t in self.targets:
            if not self.seentarget(t):
                self.addseentarget(t)
                self.searchTarget(t, '', '', '')
            for user in self.getUsers(t):
                passwords = KeyStore.get([f'creds/host/{t}/username/{user}/password'])

                for password in passwords:
                    if not self.seentarget(t + user + password):
                        self.addseentarget(t + user + password)
                        self.searchTarget(t, user, password, "")
            domains = KeyStore.get(f"host/{t}/domain")
            for domain in domains:
                for user in self.getDomainUsers(domain):
                    passwords = KeyStore.get([f'creds/domain/{t}/username/{user}/password'])
                    for password in passwords:
                        if not self.seentarget(t + user + password + domain):
                            self.addseentarget(t + user + password + domain)
                            self.searchTarget(t, user, password, domain)
        return
