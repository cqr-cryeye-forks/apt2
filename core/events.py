import queue
import time
from threading import Thread


class ActiveThreadListItem:
    def __init__(self, thread, name):
        self.thread = thread
        self.name = name

    def getThread(self):
        return self.thread

    def getName(self):
        return self.name


class EventObject:
    def __init__(self, _instance, vector, event):
        self._instance = _instance
        self.vector = vector
        self.event = event

    def get_event(self):
        return self.event

    def get_name(self):
        return self._instance.getShortName()

    def get_instance(self):
        return self._instance

    def get_vector(self):
        return self.vector


class EventQueue():
    eventQueue = queue.Queue()

    @staticmethod
    def pop():
        return EventQueue.eventQueue.get()

    @staticmethod
    def push(evtobj):
        # print("NEW EVENT: " + evtobj.get_event())
        EventQueue.eventQueue.put(evtobj)
        return

    @staticmethod
    def empty():
        return EventQueue.eventQueue.empty()

    @staticmethod
    def size():
        return EventQueue.eventQueue.qsize()


class EventHandler(object):
    eventList = {}
    nameList = list()
    my_threads = list()
    ActiveThreadCountThread = False

    @staticmethod
    def add(_instance, event):
        if event in EventHandler.eventList:
            EventHandler.eventList[event].append(_instance)
        else:
            EventHandler.eventList[event] = [_instance]

    @staticmethod
    def remove(_instance, event):
        if event in EventHandler.eventList:
            EventHandler.eventList[event].remove(_instance)

    @staticmethod
    def fire(event):
        parts = event.split(":")
        event = parts[0]
        vector = parts[1] if len(parts) == 2 else ""
        if f"{event}:{vector}" not in EventHandler.nameList and event in EventHandler.eventList:
            for _instance in EventHandler.eventList[event]:
                EventQueue.push(EventObject(_instance, vector, event))
                EventHandler.nameList.append(f"{event}:{vector}")

    @staticmethod
    def numActiveThreads(name):
        num = 0
        for t in EventHandler.my_threads:
            if t.getName() == name:
                num = num + 1
        return num

    @staticmethod
    def colapsethreads():
        tmp_threads = [t for t in EventHandler.my_threads if t.getThread().is_alive()]
        EventHandler.my_threads = tmp_threads

    @staticmethod
    def finished():
        EventHandler.colapsethreads()
        return bool(EventQueue.empty() and (len(EventHandler.my_threads) == 0))

    @staticmethod
    def kill_thread_count_thread():
        EventHandler.ActiveThreadCountThread = False

    @staticmethod
    def print_thread_count(display, delay=5):
        EventHandler.ActiveThreadCountThread = True
        while EventHandler.ActiveThreadCountThread:
            while EventHandler.ActiveThreadCountThread and len(EventHandler.my_threads) == 0:
                time.sleep(delay)
            display.alert("Current # of Active Threads = [%i]" %
                          len(EventHandler.my_threads))
            tmp_list = ""
            for t in EventHandler.my_threads:
                if tmp_list != "":
                    tmp_list = f"{tmp_list}, "
                tmp_list = tmp_list + t.getName()
            display.alert(f"    ==> {tmp_list}")
            display.debug("EventQueue Size = [%i]" % EventQueue.size())
            time.sleep(delay)

    @staticmethod
    def processNext(display, max_threads):
        while len(EventHandler.my_threads) >= max_threads:
            EventHandler.colapsethreads()
        if not EventQueue.empty():
            evtobj = EventQueue.pop()
            _instance = evtobj.get_instance()
            vector = evtobj.get_vector()
            event = evtobj.get_event()
            EventHandler.nameList.remove(f"{event}:{vector}")
            if _instance and EventHandler.numActiveThreads(_instance.getShortName()) >= int(_instance.getMaxThreads()):
                EventHandler.fire(f"{event}:{vector}")
            else:
                display.verbose(f"Launching [{_instance.getTitle()}] Vector [{vector}]")
                if _instance:
                    thread = Thread(target=_instance.go, args=(vector, ), daemon=True)
                    thread.start()
                    EventHandler.my_threads.append(ActiveThreadListItem(thread, _instance.getShortName()))
                    # _instance.go(vector)
