import re

from core.actionModule import actionModule
from core.keystore import KeyStore
from core.utils import Utils


class scan_rpcclient_userenum(actionModule):
    def __init__(self, config, display, lock):
        super(scan_rpcclient_userenum, self).__init__(config, display, lock)
        self.title = "Get List of Users From SMB"
        self.shortName = "UserEnumRpcClient"
        self.description = "execute [rpcclient -U \"\" -N <IP> -c enumdomusers] on each target"

        self.requirements = ["rpcclient", "nmblookup"]
        self.triggers = ["nullSession"]

        self.safeLevel = 5

    def getTargets(self):
        # we are interested only in the hosts that had null sessions
        self.targets = KeyStore.get('vuln/host/*/nullSession')

    def chunk(self, l, n):
        for i in range(0, len(l), n):
            yield l[i:i + n]

    def sids2names(self, ip, sid, start, stop):
        rid_accounts = []
        ranges = [f'{sid}-{rid}' for rid in range(start, stop)]
        chunk_size = 2500
        chunks = list(self.chunk(ranges, chunk_size))
        for c in chunks:
            command = self.config["rpcclient"] + ' -U "" %s -N -c "lookupsids ' % ip
            command += ' '.join(c)
            command += '"'
            result = Utils.execWait(command, None)
            if "NT_STATUS_ACCESS_DENIED" in result:
                break
            for line in result.rstrip().split('\n'):
                if "*unknown*" not in line and line != "":
                    rid_account = line.split(" ", 1)[1]
                    if rid_account != "request" and '00000' not in rid_account and '(1)' in rid_account:
                        rid_account = rid_account.replace("(1)", "")
                        rid_account = rid_account.rstrip()
                        rid_accounts.append(rid_account)
        return rid_accounts

    def process(self):
        # load any targets we are interested in
        self.getTargets()

        # loop over each target
        for t in self.targets:
            # verify we have not tested this host before
            if not self.seentarget(t):
                # add the new IP to the already seen list
                self.addseentarget(t)
                self.display.verbose(f"{self.shortName} - Connecting to {t}")

                # get windows domain/workgroup
                temp_file2 = self.config["proofsDir"] + "nmblookup_" + t + "_" + Utils.getRandStr(10)
                command2 = self.config["nmblookup"] + " -A " + t
                result2 = Utils.execWait(command2, temp_file2)
                workgroup = "WORKGROUP"
                for line in result2.split('\n'):
                    if m := re.match(r'\s+(.*)\s+<00> - <GROUP>.*', line):
                        workgroup = m[1].strip()
                        self.display.debug(f"found ip [{t}] is on the workgroup/domain [{workgroup}]")

                # add the current host to the domain in the KeyStore
                KeyStore.add(f'host/{t}domain/{workgroup}')

                # make outfile
                temp_file = self.config["proofsDir"] + self.shortName + "_" + t + "_" + Utils.getRandStr(10)

                # run rpcclient
                command = self.config["rpcclient"] + " -N -U \"\" " + t + " -c enumdomusers"
                result = Utils.execWait(command, temp_file)

                # check to see if it worked
                if any(x in result for x in ["NT_STATUS_LOGON_FAILURE", "NT_STATUS_ACCESS_DENIED"]):
                    sid = False
                    # pull the domain via lsaenum
                    result2: str = Utils.execWait(self.config["rpcclient"] + ' -U "" %s -N -c "lsaquery"' % t, None)
                    # if the user wasn't found, return a False
                    if "Domain Sid" in result2:
                        sid = result2
                    if sid:
                        sid = sid.replace("WARNING: Ignoring invalid value 'share' for parameter 'security'", "")
                        # format it properly
                        sid = sid.rstrip()
                        sid = sid.split(" ")
                        sid = sid[4]
                        rid_start = 500
                        rid_stop = 10000
                        if sid_names := self.sids2names(t, sid, rid_start, rid_stop):
                            for name in sid_names:
                                # fire a new trigger
                                self.fire("newUser")

                                if m := re.match(r'(.*)\\(.*)', name):
                                    self._extracted_from_process_59(t, m, 2, workgroup)
                else:

                    # loop over each returned user and add it to the KeyStore
                    for line in result.split('\n'):
                        if m := re.match(r'user:\[(.*)] rid:\[(.*)].*', line):
                            # fire a new trigger
                            self.fire("newUser")

                            self._extracted_from_process_59(t, m, 1, workgroup)
        return

    # TODO Rename this here and in `process`
    def _extracted_from_process_59(self, t, m, arg2, workgroup):
        self.display.debug(f"IP [{t}] has local user [{m[arg2]}]")
        KeyStore.add(f'creds/host/{t}/username/{m[arg2]}')
        if workgroup != "WORKGROUP":
            self.display.debug(f"Domain [{workgroup}] has user [{m[arg2]}]")
            KeyStore.add(f'creds/domain/{workgroup}/username/{m[arg2]}')
