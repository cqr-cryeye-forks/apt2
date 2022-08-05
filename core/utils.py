import configparser
import contextlib
import fcntl
import os
import random
import socket
import string
import struct
import subprocess
import sys
import threading
import time


class Utils:
    @staticmethod
    def port_open(ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((ip, int(port)))
        return result == 0

    @staticmethod
    def to_unicode_str(obj, encoding='utf-8'):
        # checks if obj is a string and converts if not
        if not isinstance(obj, str):
            obj = str(obj)
        obj = Utils.to_unicode(obj, encoding)
        return obj

    @staticmethod
    def to_unicode(obj, encoding='utf-8'):
        return str(obj)

    @staticmethod
    def newLine():
        return os.linesep

    @staticmethod
    def isWriteable(filename):
        try:
            fp = open(filename, 'a')
            fp.close()
            return True
        except IOError:
            return False

    @staticmethod
    def isReadable(filename):
        try:
            fp = open(filename, 'r')
            fp.close()
            return True
        except IOError:
            return False

    @staticmethod
    def isExecutable(filename):
        return Utils.fileExists(filename) and os.access(filename, os.X_OK)

    @staticmethod
    def fileExists(filename):
        return os.path.isfile(filename)

    @staticmethod
    def writeFile(text, filename):
        if not Utils.isWriteable(filename):
            return
        if text:
            full_file_name = os.path.abspath(filename)
            if not os.path.exists(os.path.dirname(full_file_name)):
                os.makedirs(os.path.dirname(full_file_name))
            with open(full_file_name, "a") as fp:
                fp.write(text)

    @staticmethod
    def readFile(filename):
        text = []
        if not Utils.isReadable(filename):
            return text
        with open(filename) as f:
            text = f.read().splitlines()
        return text

    @staticmethod
    def validateExecutable(name):
        tmp = Utils.execWait(f"which {name}").strip()
        return tmp if tmp and tmp != "" and Utils.isExecutable(tmp) else None

    @staticmethod
    def getRandStr(length):
        return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))

    @staticmethod
    def load_config(filename):
        config = {}
        if Utils.isReadable(filename):
            parser = configparser.SafeConfigParser()
            parser.read(filename)
            for section_name in parser.sections():
                for name, value in parser.items(section_name):
                    config[name] = value
        return config

    @staticmethod
    def uniqueList(old_list):
        new_list = []
        if old_list:
            for x in old_list:
                if x not in new_list:
                    new_list.append(x)
        return new_list

    @staticmethod
    def execWait(cmd, outfile=None, timeout=0):
        env = os.environ
        proc = subprocess.Popen(cmd, executable='/bin/bash', env=env,
                                stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True)

        timer = threading.Timer(timeout, proc.kill)
        if timeout:
            timer.start()
        result = proc.communicate()[0]
        if timeout and timer.is_alive():
            timer.cancel()
        if outfile:
            if Utils.fileExists(outfile):
                print("FILE ALREADY EXISTS!!!!")
            else:
                tmp_result = f'\033[0;33m({time.strftime("%Y.%m.%d-%H.%M.%S")}) <pentest> ' \
                             f'#\033[0m {cmd}{Utils.newLine()}{Utils.newLine()}{result}'
                Utils.writeFile(tmp_result, outfile)
        return result

    @staticmethod
    def webScreenCap(url, outfile):
        cmd = 'phantomjs --ssl-protocol=any --ignore-ssl-errors=yes misc/capture.js "%s" "%s"' % (url, outfile)
        Utils.execWait(cmd)
        return

    @staticmethod
    def getInterfaceIP(interface_name):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', bytes(interface_name[:15].encode())))[20:24])

    @staticmethod
    def getIP():
        try:
            ip = socket.gethostbyname(socket.gethostname())
            if ip.startswith("127."):
                interfaces = ["eth0", "eth1", "eth2", "wlan0", "wlan1", "wifi0", "ath0", "ath1", "ppp0"]

                for interface_name in interfaces:
                    with contextlib.suppress(IOError):
                        ip = Utils.getInterfaceIP(interface_name)
                        break
            return ip
        except socket.gaierror:
            return None

    @staticmethod
    def getUnusedPort():
        return 0


class Colors:
    NATIVE = '\033[m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    ORANGE = '\033[33m'
    BLUE = '\033[34m'


class ProgressBar:
    def __init__(self, end=100, width=10, title="", display=None):
        self.end = end
        self.width = width
        self.title = title
        self.display = display
        self.progress = float(0)
        self.bar_format = '[%(fill)s>%(blank)s] %(progress)s%% - %(title)s'
        self.rotate_format = '[Processing: %(mark)s] %(title)s'
        self.markers = '|/-\\'
        self.cur_mark = -1
        self.completed = False
        self.reset()

    def reset(self, end=None, width=None, title=""):
        self.progress = float(0)
        self.completed = False
        if end:
            self.end = end
        if width:
            self.width = width
        self.cur_mark = -1
        self.title = title

    def inc(self, num=1):
        if not self.completed:
            self.progress += num

            cur_width = (self.progress / self.end) * self.width
            fill = int(cur_width) * "-"
            blank = (self.width - int(cur_width)) * " "
            percentage = int((self.progress / self.end) * 100)

            if self.display:
                self.display.verbose(
                    self.bar_format % {'title': self.title, 'fill': fill, 'blank': blank, 'progress': percentage},
                    rewrite=True, end="", flush=True)
            else:
                sys.stdout.write('\r' + self.bar_format % {'title': self.title, 'fill': fill, 'blank': blank,
                                                           'progress': percentage})
                sys.stdout.flush()

            if self.progress == self.end:
                self.done()
        return self.completed

    def done(self):
        self.completed = True

    def rotate(self):
        if not self.completed:
            self.cur_mark = (self.cur_mark + 1) % len(self.markers)
            if self.display:
                self.display.verbose(self.rotate_format % {'title': self.title, 'mark': self.markers[self.cur_mark]},
                                     rewrite=True, end="", flush=True)
            else:
                sys.stdout.write('\r' + self.rotate_format % {'title': self.title, 'mark': self.markers[self.cur_mark]})
                sys.stdout.flush()
        return self.completed


class Display:
    def __init__(self, verbose=False, debug=False, log_path=None):
        self.VERBOSE = verbose
        self.DEBUG = debug
        self.log_path = log_path
        self.ruler = '-'

    def setLogPath(self, log_path):
        self.log_path = log_path

    def enableVerbose(self):
        self.VERBOSE = True

    def enableDebug(self):
        self.DEBUG = True

    def log(self, s, filename="processlog.txt"):
        if self.log_path is not None:
            full_file_name = self.log_path + filename
            if not os.path.exists(os.path.dirname(full_file_name)):
                os.makedirs(os.path.dirname(full_file_name))
            with open(full_file_name, "a") as fp:
                if filename == "processlog.txt":
                    fp.write(time.strftime("%Y.%m.%d-%H.%M.%S") + " - " + s + "\n")
                else:
                    fp.write(s)

    def _display(self, line, end="\n", flush=True, rewrite=False):
        if rewrite:
            line = '\r' + line
        sys.stdout.write(line + end)
        if flush:
            sys.stdout.flush()
        self.log(line)

    def error(self, line="", end="\n", flush=True, rewrite=False):
        """Formats and presents errors."""
        line = line[:1].upper() + line[1:]
        s = f'{Colors.RED}[!] {Utils.to_unicode(line)}{Colors.NATIVE}'
        self._display(s, end=end, flush=flush, rewrite=rewrite)

    def output(self, line="", end="\n", flush=True, rewrite=False):
        """Formats and presents normal output."""
        s = f'{Colors.BLUE}[*]{Colors.NATIVE} {Utils.to_unicode(line)}'
        self._display(s, end=end, flush=flush, rewrite=rewrite)

    def alert(self, line="", end="\n", flush=True, rewrite=False):
        """Formats and presents important output."""
        s = f'{Colors.ORANGE}[*] {Utils.to_unicode(line)}{Colors.NATIVE}'
        self._display(s, end=end, flush=flush, rewrite=rewrite)

    def verbose(self, line="", end="\n", flush=True, rewrite=False):
        """Formats and presents output if in verbose mode."""
        if self.VERBOSE:
            self.output(f"[VERBOSE] {line}", end=end, flush=flush, rewrite=rewrite)

    def debug(self, line="", end="\n", flush=True, rewrite=False):
        """Formats and presents output if in debug mode (very verbose)."""
        if self.DEBUG:
            # import inspect
            # prev_frame = inspect.currentframe().f_back.f_back.f_back.f_back
            # self.output("[DEBUG]   " + inspect.getframeinfo(prev_frame).filename + ":" +
            # str(inspect.getframeinfo(prev_frame).lineno), end=end, flush=flush, rewrite=rewrite)
            self.output(f"[DEBUG]   {line}", end=end, flush=flush, rewrite=rewrite)

    def yn(self, line, default=None):
        valid = {"yes": True, "y": True, "no": False, "n": False}
        prompt = " [y/n] "
        if default is None:
            prompt = " [y/n] "
        elif default.lower() in ["yes", "y"]:
            prompt = " [Y/n] "
        elif default.lower() in ["no", "n"]:
            prompt = " [y/N] "
        else:
            self.alert("ERROR: Please provide a valid default value: no, n, yes, y, or None")

        while True:
            choice = self.input_string(line + prompt)
            if default is not None and choice == '':
                return valid[default.lower()]
            elif choice.lower() in valid:
                return valid[choice.lower()]
            else:
                self.alert("Please respond with 'yes/no' or 'y/n'.")

    def select_list(self, line, input_list):
        answers = []
        if not input_list:
            return answers
        i = 1
        for item in input_list:
            self.output(f"{str(i)}: {str(item)}")
            i = i + 1
        choice = self.input_string(line)
        if not choice:
            return answers
        answers = choice.replace(' ', '').split(',')
        return answers

    @staticmethod
    def input_string(line):
        """Formats and presents an input request to the user"""
        s = f'{Colors.ORANGE}[?]{Colors.NATIVE} {Utils.to_unicode(line)}'
        return input(s)

    def heading(self, line):
        """Formats and presents styled header text"""
        line = Utils.to_unicode(line)
        self.output(self.ruler * len(line))
        self.output(line.upper())
        self.output(self.ruler * len(line))

    def print_list(self, title, _list):
        self.heading(title)
        if _list:
            for item in _list:
                self.output(item)
        else:
            self.output("None")

    def print_module_list(self, modules):
        """Print a listing of available modules"""

        module_len = 6
        type_len = 4
        safety_len = 12
        desc_len = 11

        for module in modules:

            if len(modules[module]['name']) > module_len:
                module_len = len(modules[module]['name'])
            if len(modules[module]['type']) > type_len:
                type_len = len(modules[module]['type'])
            if modules[module]['safelevel'] and len(str(modules[module]['safelevel'])) > safety_len:
                safety_len = len(str(modules[module]['safelevel']))
            if len(modules[module]['description']) > desc_len:
                desc_len = len(modules[module]['description'])

        self.output("+-" + "".ljust(module_len, "-") + "-+-" + "".ljust(type_len, "-") + "-+-" +
                    "".ljust(safety_len, "-") + "-+-" + "".ljust(desc_len, "-") + "-+")
        self.output("| " + "Module".ljust(module_len) + " | " + "Type".ljust(type_len) + " | " +
                    "Safety_Level".ljust(safety_len) + " | " + "Description".ljust(desc_len) + " |")
        self.output("+-" + "".ljust(module_len, "-") + "-+-" + "".ljust(type_len, "-") + "-+-" +
                    "".ljust(safety_len, "-") + "-+-" + "".ljust(desc_len, "-") + "-+")

        sort_modules = sorted(modules, key=lambda x: (modules[x]['type'], modules[x]['name']))
        for module in sort_modules:
            self.output("| " + modules[module]['name'].ljust(module_len) + " | " +
                        modules[module]['type'].ljust(type_len) + " | " +
                        str(modules[module]['safelevel']).ljust(safety_len) + " | " +
                        modules[module]['description'].ljust(desc_len) + " |")

        self.output("+-" + "".ljust(module_len, "-") + "-+-" + "".ljust(type_len, "-") + "-+-" +
                    "".ljust(safety_len, "-") + "-+-" + "".ljust(desc_len, "-") + "-+")

# -----------------------------------------------------------------------------
# main test code
# -----------------------------------------------------------------------------
