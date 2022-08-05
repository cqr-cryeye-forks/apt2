import argparse
import contextlib
import imp
import os
import re
import sys
from os.path import expanduser
from threading import RLock, Thread

import pkg_resources

from .events import EventHandler
from .keyeventthread import KeyEventThread
from .keystore import KeyStore
from .mymsf import MyMsf
from .mynmap import MyNmap
# import our libs
from .utils import Utils, Display


class Framework:
    def __init__(self):
        self.display = Display()
        self.module_lock = RLock()
        self.InputModules = {}
        self.actionModules = {}
        self.reportModules = {}
        self.progName = "APT2"
        self.version = "None"
        with contextlib.suppress(Exception):
            self.version = pkg_resources.get_distribution("apt2").version
        if Utils.isReadable('VERSION'):
            version_pattern = r"'(\d+\.\d+\.\d+[^']*)'"
            self.version = re.search(version_pattern, open('VERSION').read())[1]
        self.isRunning = True
        self.inputs = {}
        home_dir = expanduser("~")
        self.config: dict = {
            "homeDir": home_dir,
            "outDir": f"{home_dir}/.apt2/",
            "reportDir": "",
            "logDir": "",
            "proofsDir": "",
            "tmpDir": "",
            "pkgDir": f"{os.path.dirname(os.path.dirname(os.path.abspath(__file__)))}/",
            "miscDir": "",
            'lhost': Utils.getIP(),
            "config_filename": "",
            "verbose": False,
            "always_yes": False,
            "list_modules": False,
            "scan_target": None,
            "scan_target_list": None,
            "safe_level": 4,
            "exclude_types": "",
        }

        self.setup_dirs()
        self.kbSaveFile = f'{self.config["proofsDir"]}KB-{Utils.getRandStr(10)}.save'

        self.thread_count_thread = None
        self.key_event_thread = None
        self.allFinished = False

    # ==================================================
    # SUPPORT METHODS
    # ==================================================

    # ----------------------------
    # Setup Directories
    # ----------------------------
    def setup_dirs(self):
        if not os.path.isdir(self.config["outDir"]):
            os.makedirs(self.config["outDir"])
        self.update_dirs("reports/", "reportDir", "logs/", "logDir")
        self.display.setLogPath(self.config["logDir"])
        self.update_dirs("proofs/", "proofsDir", "tmp/", "tmpDir")
        if not os.path.isdir(f'{self.config["pkgDir"]}misc/'):
            os.makedirs(f'{self.config["pkgDir"]}misc/')
        self.config["miscDir"] = f'{self.config["pkgDir"]}misc/'

    def update_dirs(self, arg0, arg1, arg2, arg3):
        if not os.path.isdir(f'{self.config["outDir"]}{arg0}'):
            os.makedirs(f'{self.config["outDir"]}{arg0}')
        self.config[arg1] = f'{self.config["outDir"]}{arg0}'
        if not os.path.isdir(f'{self.config["outDir"]}{arg2}'):
            os.makedirs(f'{self.config["outDir"]}{arg0}')
        self.config[arg3] = f'{self.config["outDir"]}{arg0}'

    # ----------------------------
    # CTRL-C display and exit
    # ----------------------------
    def ctrlc(self):
        self.display.alert("Ctrl-C caught!!!")

        self.cleanup()

    # ----------------------------
    # Close everything down nicely
    # ----------------------------
    def cleanup(self):
        # kill key press thread if it has been set up
        if self.key_event_thread:
            self.key_event_thread.stop()

        # kill thread count thread
        EventHandler.kill_thread_count_thread()

        # fix prompt
        os.system("stty echo")

        # exit
        sys.exit(0)

    # ----------------------------
    # Display the Banner
    # ----------------------------
    # noinspection SpellCheckingInspection
    def display_banner(self):
        self._print_extra_banner("      dM.    `MMMMMMMb. MMMMMMMMMM      ",
                                 "     ,MMb     MM    `Mb /   MM   \      ")

        self.display.output("     d'YM.    MM     MM     MM   ____   ")
        self.display.output("    ,P `Mb    MM     MM     MM  6MMMMb  ")
        self.display.output("    d'  YM.   MM    .M9     MM MM'  `Mb ")
        self.display.output("   ,P   `Mb   MMMMMMM9'     MM      ,MM ")
        self.display.output("   d'    YM.  MM            MM     ,MM' ")
        self.display.output("  ,MMMMMMMMb  MM            MM   ,M'    ")
        self.display.output("  d'      YM. MM            MM ,M'      ")
        self.display.output("_dM_     _dMM_MM_          _MM_MMMMMMMM ")
        self.display.output()
        self._print_extra_banner("An Automated Penetration Testing Toolkit", "Written by: Adam Compton & Austin Lane")

        self.display.output(f"Verion: {self.version}")

    def _print_extra_banner(self, arg0, arg1):
        self.display.output()
        self.display.output(arg0)
        self.display.output(arg1)

    # ----------------------------
    # Parse CommandLine Params
    # ----------------------------
    def parse_parameters(self, argv):
        parser = argparse.ArgumentParser()
        files_group = parser.add_argument_group('inputs')
        files_group.add_argument("-C", metavar="<config.txt>", dest="config_file", action='store', help="config file")

        files_group.add_argument("-f", metavar="<input file>", dest="inputs", default=[], action='store',
                                 help="one of more input files seperated by spaces", nargs='*')

        files_group.add_argument("--target", metavar="", dest="scan_target", action='store',
                                 help="initial scan target(s)")

        adv_group = parser.add_argument_group('advanced')
        adv_group.add_argument("--ip", metavar="<local IP>", dest="lhost", default=Utils.getIP(), action='store',
                               help=f"defaults to {Utils.getIP()}")

        parser.add_argument("-v", "--verbosity", dest="verbose", action='count', help="increase output verbosity")

        parser.add_argument("-s", "--safelevel", dest="safe_level", action='store', default=4,
                            help="set min safe level for modules. 0 is unsafe and 5 is very safe. Default is 4")

        parser.add_argument("-x", "--exclude", dest="exclude_types", action="store", default="",
                            help="specify a comma seperated list of module types to exclude from running")

        misc_group = parser.add_argument_group('misc')
        misc_group.add_argument("--listmodules", dest="list_modules", action='store_true',
                                help="list out all current modules and exit")

        args = parser.parse_args()
        self.config["config_filename"] = args.config_file
        self.config["verbose"] = args.verbose
        self.config["list_modules"] = args.list_modules
        self.config["scan_target"] = args.scan_target
        self.config["safe_level"] = int(args.safe_level)
        self.config["exclude_types"] = args.exclude_types
        self.config['lhost'] = args.lhost
        for f in args.inputs:
            if Utils.isReadable(f):
                if type := self.idFileType(f):
                    if type in self.inputs:
                        self.inputs[type].append(f)
                    else:
                        self.inputs[type] = [f]
            else:
                print(f"Can not access [{f}]")

    # ----------------------------
    # Load config setting from the config file
    # ----------------------------
    def loadConfig(self):
        # does config file exist?
        if ("config_filename" in self.config) and (self.config["config_filename"] is not None):
            temp1 = self.config
            temp2 = Utils.loadConfig(self.config["config_filename"])
            self.config = dict(list(temp2.items()) + list(temp1.items()))
        elif Utils.isReadable(f'{self.config["miscDir"]}default.cfg'):
            self.display.verbose("a CONFIG FILE was not specified...  defaulting to [default.cfg]")
            temp1 = self.config
            temp2 = Utils.loadConfig(f'{self.config["miscDir"]}default.cfg')
            self.config = dict(list(temp2.items()) + list(temp1.items()))
        else:
            # someone must have removed it!
            self.display.error("a CONFIG FILE was not specified...")
            self.cleanup()

        # set verbosity/debug level
        if "verbose" in self.config:
            verbose = self.config['verbose'] or 0
            if verbose >= 1:
                self.display.enableVerbose()
            if verbose > 1:
                self.display.enableDebug()

        if self.config["lhost"] is None or self.config["lhost"] == "":
            self.display.error("No IP was able to be determined and one was not provided.")
            self.display.error("Please specify one via the [--ip <ip>] argument.")
            self.cleanup()

    # ----------------------------
    # Load Initial Events
    # ----------------------------
    def populateInitEvents(self):
        EventHandler.fire("always:initial")

    # ----------------------------
    # look for and load and modules (input/action)
    # ----------------------------
    def loadModules(self):
        module_dict = {}
        path = os.path.join(self.config["pkgDir"], 'modules/input')
        for dir_path, dir_names, filenames in os.walk(path):
            filenames = [f for f in filenames if f[0] != '.']
            dir_names[:] = [d for d in dir_names if d[0] != '.']
            if filenames:
                for filename in [f for f in filenames if f.endswith('.py') and f != "__init__.py"]:
                    module = self.loadModule("input", dir_path, filename)
                    if module is not None:
                        module_dict[module['name'].rstrip(" ")] = module
        path = os.path.join(self.config["pkgDir"], 'modules/action')
        for dir_path, dir_names, filenames in os.walk(path):
            filenames = [f for f in filenames if f[0] != '.']
            dir_names[:] = [d for d in dir_names if d[0] != '.']
            if filenames:
                for filename in [f for f in filenames if f.endswith('.py') and f != "__init__.py"]:
                    module = self.loadModule("action", dir_path, filename)
                    if module is not None:
                        module_dict[module['name'].rstrip(" ")] = module
        path = os.path.join(self.config["pkgDir"], 'modules/report')
        for dir_path, dir_names, filenames in os.walk(path):
            filenames = [f for f in filenames if f[0] != '.']
            dir_names[:] = [d for d in dir_names if d[0] != '.']
            if filenames:
                for filename in [f for f in filenames if f.endswith('.py') and f != "__init__.py"]:
                    module = self.loadModule("report", dir_path, filename)
                    if module is not None:
                        module_dict[module['name'].rstrip(" ")] = module
        return module_dict

    # ----------------------------
    # check to see if the module is of an exclude module type
    # ----------------------------
    def checkExcludeTypes(self, types):
        for t in types:
            for T in self.config["exclude_types"].split(','):
                if t == T:
                    return True
        return False

    # ----------------------------
    # load each module
    # ----------------------------
    def loadModule(self, type, dir_path, filename):
        base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        dir_path_orig = dir_path
        dir_path = dir_path[len(base_path) + 1:]
        mod_name = filename.split('.')[0]
        mod_display_name = '/'.join(re.split(f'/modules/{type}/', dir_path)[-1].split('/') + [mod_name])

        mod_load_name = mod_display_name.replace('/', '_')
        mod_load_path = os.path.join(dir_path_orig, filename)
        mod_file = open(mod_load_path)
        try:
            imp.load_source(mod_load_name, mod_load_path, mod_file)
            _module = __import__(mod_load_name)
            _class = getattr(_module, mod_name)
            _instance = _class(self.config, self.display, self.module_lock)
            reasons = []
            valid = True
            for r in _instance.getRequirements():
                if r == 'disable':
                    reasons.append("Module Manually Disabled !!!")
                elif r == 'APIKEY':
                    key_name = f"{mod_name}_apikey"
                    if key_name not in self.config:
                        reasons.append("API key is missing")
                        valid = False
                elif r not in self.config:
                    if path := Utils.validateExecutable(r):
                        self.config[r] = path
                    else:
                        reasons.append(f"Requirement not met: {r}")
                        valid = False
            if valid:
                module_dict = {'name': mod_name.ljust(25), 'description': _instance.getTitle().ljust(40),
                               'type': type.ljust(6), 'valid': True}

            else:
                module_dict = {'name': mod_name.ljust(25), 'description': _instance.getTitle().ljust(40),
                               'type': type.ljust(6), 'valid': False}

            if type == 'action':
                module_dict['safelevel'] = _instance.getSafeLevel()
            else:
                module_dict['safelevel'] = None
            if valid:
                if type == "action":
                    if self.config["safe_level"] > _instance.getSafeLevel():
                        reasons.append(("Safety_Level (%i) is below requirement: %i" % (
                            _instance.getSafeLevel(), self.config["safe_level"])))

                    elif not self.checkExcludeTypes(_instance.getTypes()):
                        self.actionModules[mod_display_name] = _instance
                        for t in _instance.getTriggers():
                            EventHandler.add(_instance, t)
                elif type == "input":
                    self.InputModules[mod_display_name] = _instance
                elif type == "report":
                    self.reportModules[mod_display_name] = _instance
            if reasons:
                self.display.error("Module \'%s\' disabled:" % mod_name)
            for r in reasons:
                self.display.error(f'     {r}')
        except ImportError as e:
            self.display.error("Module \'%s\' disabled. Dependency required: \'%s\'" % (mod_name, e))

            return None
        except Exception as e:
            print(e)
            self.display.error("Module \'%s\' disabled." % mod_name)
            return None
        return module_dict

    # ----------------------------
    # Attempt to identify the type of input file
    # ----------------------------
    def idFileType(self, filename):
        # load and read first 4096 bytes of file
        with open(filename, 'rb') as file:
            data = file.read(4086).decode()

        # get first line of the 4096 bytes
        first_line = data.split('\n', 1)[0]

        # check first_line
        if first_line.find("<NeXposeSimpleXML") != -1:
            return "nexpose_simple"
        elif first_line.find("<NexposeReport") != -1:
            return "nexpose"
        elif first_line.find("<NessusClientData>") != -1:
            return "nessus"
        elif first_line.find("<?xml") != -1:
            # it's xml, check for root tags we can handle
            for line in data.split('\n'):
                parts = re.findall(r"<([a-zA-Z0-9\-_]+)[ >]", line)
                for part in parts:
                    if part == "nmaprun":
                        return "nmap"
        else:
            return "dict"

    # ----------------------------
    # Main Menu
    # ---------------------------- 
    def displayMenu(self):
        if self.config["bypass_menu"]:
            self.runScan()  # Skip first trip through menu and go straight into a scan using whatever arguments were
            # passed
            self.isRunning = False
            return
        # fix prompt, sometimes input disappears
        os.system("stty echo")
        self.display.output()
        self.display.output("---------------------------------------")
        self.display.output()
        self.display.output("1. Run")
        self.display.output("2. NMAP Settings")
        self.display.output("3. Browse KB")
        self.display.output("4. Quit")
        self.display.output()
        try:
            userChoice = int(self.display.input("Select an option: "))
            print(f"[{userChoice}]")
            if userChoice == 1:
                # Execute scan and begin process
                self.runScan()
            elif userChoice == 2:
                # Configure NMAP Scan Settings
                self.displayNmapMenu()
            elif userChoice == 3:
                # Browse data in the KeyStore
                self.displayKbMenu()
            elif userChoice == 4:
                # Quit
                self.isRunning = False
            else:
                self.display.error(f"{userChoice} - Not a valid option")
        except ValueError:
            self.display.error("Not a valid option")

    # ----------------------------
    # Begin a Scan
    # ----------------------------
    def runScan(self):
        if self.config["scan_target"]:
            nm = MyNmap(self.config, self.display)
            nm.run(target=self.config["scan_target"], ports=self.config["scan_port_range"],
                   flags=f'-s {self.config["scan_type"]} {self.config["scan_flags"]}', vector="nmapScan",
                   file_tag="nmapScan" + self.config["scan_target"])
        elif self.config["scan_target_list"]:
            nm = MyNmap(self.config, self.display)
            nm.run(target="", ports=self.config["scan_port_range"],
                   flags=f'-s {self.config["scan_type"]} {self.config["scan_flags"]} '
                         f'-iL {self.config["scan_target_list"]}', vector="nmapScan")
        # begin main loop
        self.key_event_thread = KeyEventThread(self.display)
        self.key_event_thread.start()

        while not EventHandler.finished() or not self.allFinished:
            if EventHandler.finished() and not self.allFinished:
                EventHandler.fire("allFinished")
                self.allFinished = True
            if not self.key_event_thread.isPaused():
                EventHandler.processNext(self.display, int(self.config['max_modulethreads']))
            # KeyStore.save(self.kbSaveFile)
        # scan is done, stop checking for keypress in case we go back to the menu
        self.key_event_thread.stop()

    # ----------------------------
    # Configure NMAP Scan Settings
    # ----------------------------
    def displayNmapMenu(self):
        while True:
            self.display.output()
            self.display.output("---------------------------------------")
            self.display.output()
            self.display.output("Current NMAP Settings: ")
            self.display.output(f'Scan Type: {self.config["scan_type"]}')
            self.display.output(f'Flags: {self.config["scan_flags"]}')
            self.display.output(f'Port Range: {self.config["scan_port_range"]}')
            self.display.output(f'Target: {self.config["scan_target"]}')
            self.display.output(f'Target List: {self.config["scan_target_list"]}')
            self.display.output("Set: (s)can type, extra (f)lags, (p)ort range, (t)arget, target (l)ist, (m)ain menu")

            self.display.output()
            userChoice = self.display.input_string("Choose An Option: ")
            if userChoice == "s":
                self.config["scan_type"] = self.display.input_string("Choose S, T, U, ST, SU, TU: ")
            elif userChoice == "f":
                self.config["scan_flags"] = self.display.input_string("Set Extra Flags (ex: -A -Pn -T4): ")

            elif userChoice == "p":
                self.config["scan_port_range"] = self.display.input_string("Enter Range (1-65535): ")
            elif userChoice == "t":
                self.config["scan_target"] = self.display.input_string("Enter Target or Range (X.X.X.X/Y): ")

                self.config["scan_target_list"] = None
            elif userChoice == "l":
                filePath = self.display.input_string("Enter File Path (/tmp/targets.txt): ")
                if Utils.isReadable(filePath):
                    self.config["scan_target"] = None
                    self.config["scan_target_list"] = filePath
                else:
                    self.display.error("Unable to read file")
            elif userChoice == "m":
                break
            else:
                self.display.error(f"{userChoice} - Not a valid option")

    # ----------------------------
    # Browse Knowledgebase
    # ----------------------------
    def displayKbMenu(self):
        searchString = ""
        depth = 0
        searches: dict = {0: ""}
        self._display_data("---------------------------------------", "Browse Knowledgebase")

        while True:
            self.display.output(f"[ {searchString} ]")
            if searchString != "":
                results = KeyStore.get(searchString)
                i = 0
                for option in results:
                    self.display.output(f"{str(i)}. {option}")
                    i += 1
            else:
                self._display_data("0. host", "1. service")
                self.display.output("2. domain")
                self.display.output("3. osint")
                results = ["host", "service", "domain", "osint"]
                i = 4
            self.display.output()
            self.display.output("Choose From Above Or: (a)dd, (d)elete, (b)ack, (m)ain menu, (i)mport, "
                                "write to (t)emp file")

            self.display.output()
            search = self.display.input_string("Select option or enter custom search path: ")
            if search == "m":
                break
            elif search == "b":
                if depth > 0:
                    depth -= 1
                searchString = searches[depth]
            elif search == "a":
                text = self.display.input_string("Input new record: ")
                KeyStore.add(f'{searchString}/{text.replace("/", "|")}')
            elif search == "d":
                choice = self.display.input_string("Choose record to remove: ")
                try:
                    if int(choice) in range(i):
                        KeyStore.rm(f"{searchString}/{results[int(choice)]}")
                    else:
                        self.display.error(f"{choice} - Not a valid option")
                except ValueError:
                    self.display.error("Not a valid option")
            elif search == "i":
                self.display.error("Not implemented yet")
            elif search == "t":
                tempPath = f'{self.config["tmpDir"]}KBRESULTS-{Utils.getRandStr(10)}.txt'
                text = ""
                for line in results:
                    text += f"{line}\n"
                Utils.writeFile(text, tempPath)
                self.display.output(f"Results written to: {tempPath}")
            elif re.match("([a-zA-Z0-9.*]*/)+([a-zA-Z0-9.*]*)", search) is not None:
                searchString = search
                depth = 0
                searches[depth] = searchString
            else:
                try:
                    if int(search) in range(i):
                        searchString = results[
                            int(search)] if searchString == "" else f"{searchString}/{results[int(search)]}"

                        depth += 1
                        searches[depth] = searchString
                    else:
                        self.display.error(f"{search} - Not a valid option")
                except ValueError:
                    self.display.error(f"{search} - Not a valid option")

    def _display_data(self, arg0, arg1):
        self.display.output()
        self.display.output(arg0)
        self.display.output(arg1)

    def msfCheck(self):
        """Test to see if we can connect to the Metasploit msgrpc interface"""
        msf = MyMsf(host=self.config['msfhost'],
                    port=self.config['msfport'],
                    user=self.config['msfuser'],
                    password=self.config['msfpass'])

        if not msf.is_authenticated():
            self.display.error("Could not connect to Metasploit msgrpc service with the following parameters:")

            self.display.error(f"\thost     = [{self.config['msfhost']}]")
            self.display.error(f"\tport     = [{self.config['msfport']}]")
            self.display.error(f"\tuser     = [{self.config['msfuser']}]")
            self.display.error(f"\tpassword = [{self.config['msfpass']}]")
            self.display.alert("If you wish to make use of Metasploit modules within APT2, please update the config "
                               "file with the appropriate settings.")

            self.display.error("Connect by launching msfconsole and then issue the following commands:")

            self.display.error(f'\tload msgrpc User={self.config["msfuser"]} Pass={self.config["msfpass"]} '
                               f'ServerPort={self.config["msfport"]}')

            self.display.error(f'\tresource {self.config["miscDir"]}apt2.rc')
            self.display.output()

    def modulesLoaded(self):
        """Print Loaded Module Stats"""
        self.display.output("Input Modules Loaded:\t%i" % len(self.InputModules))
        self.display.output("Action Modules Loaded:\t%i" % len(self.actionModules))
        self.display.output("Report Modules Loaded:\t%i" % len(self.reportModules))

    def additionalInfo(self):
        """Print Additional Information such as knowledge base path and current IP address"""
        self.display.output()
        self.display.alert(f"The KnowledgeBase will be auto saved to : {self.kbSaveFile}")
        self.display.alert(f"Local IP is set to : {self.config['lhost']}")
        self.display.alert(
            "\t If you would rather use a different IP, then specify it via the [--ip <ip>] argument.")

    # ==========================================================================================
    # ==========================================================================================
    # ==========================================================================================

    # ----------------------------
    # Primary METHOD
    # ----------------------------

    def run(self, argv):
        # os.system('clear')
        self.parse_parameters(argv)
        self.display_banner()  # Print banner first and all messages after
        self.loadConfig()  # load config
        modules_dict = self.loadModules()  # load input/action modules
        self.modulesLoaded()

        if self.config["list_modules"]:
            self.display.print_module_list(modules_dict)
            sys.exit()

        self.additionalInfo()
        self.msfCheck()

        # parse inputs
        for input_key in list(self.inputs.keys()):
            for input_module in list(self.InputModules.keys()):
                _instance = self.InputModules[input_module]
                if _instance.getType() == input_key:
                    for file in self.inputs[input_key]:
                        self.display.verbose(f"Loading [{file}] with [{input_module}]")
                        _instance.go(file)

        # populate any initial events
        self.populateInitEvents()

        # begin menu loop
        self.thread_count_thread = Thread(target=EventHandler.print_thread_count, args=(self.display,))
        self.thread_count_thread.start()
        self.runScan()  # Skip first trip through menu and go straight into a scan using whatever arguments were passed
        self.isRunning = False
        #        while self.isRunning:
        #            self.displayMenu()

        if KeyStore:
            KeyStore.save(self.kbSaveFile)

        # generate reports
        self.display.output("Generating Reports")
        for report_module in list(self.reportModules.keys()):
            _instance = self.reportModules[report_module]
            _instance.process()

        self.display.output()
        self.display.output("Good Bye!")
        self.cleanup()
