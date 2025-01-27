import ast
import sys

try:
    from unqlite import UnQLite
except ImportError:
    sys.exit("[!] Install the UnQlite library: pip install unqlite")

from .utils import Utils


class KeyStore:
    db = UnQLite()

    # =================================================
    # "private" methods
    # =================================================

    # get the list of values for a given key
    @staticmethod
    def _get(item):
        item = item.rstrip('/')
        values = []
        if "/*/" in item:
            parts = item.split("*")
            left = parts[0].split()[-1]
            right = parts[1].split()[0] if parts[1].split() else ''
            temp_vals = KeyStore.get(left)
            if isinstance(temp_vals, str):
                temp_vals = ast.literal_eval(temp_vals)
            values.extend(temp_val for temp_val in temp_vals if f"{left}{temp_val}{right}" in KeyStore.db)

        elif item in KeyStore.db:
            values = KeyStore.db[item]
        return values

    # =================================================
    # "public" methods
    # =================================================

    # Set a new value within the keystore
    @staticmethod
    def add(item):
        item = item.rstrip('/')
        if item not in KeyStore.db:
            KeyStore.db[item] = []
        if item.count('/') > 0:
            key, value = item.rsplit('/', 1)
            value = str(value)
            values = KeyStore._get(key) if key in KeyStore.db else []
            if type(values) is bytes:
                values = ast.literal_eval(values.decode('utf-8'))
            if value not in values:
                values.append(value)
                KeyStore.db[key] = values
                KeyStore.add(key)

    # return a list of values for a given key
    @staticmethod
    def get(*items):
        result = []
        for item in items:
            r2 = KeyStore._get(item)
            if isinstance(r2, str):
                r2 = ast.literal_eval(r2)
            result += r2
        return list(sorted(set(result))) if result else []

    # remove a given key or value
    @staticmethod
    def rm(key):
        return

    # print out current KeyStore
    @staticmethod
    def debug():
        with KeyStore.db.cursor() as cursor:
            for key, value in cursor:
                print(key, '=>', value)
        return

    # dump keystore to text
    @staticmethod
    def dump():
        dump = ""
        with KeyStore.db.cursor() as cursor:
            for key, values in cursor:
                values = ast.literal_eval(values.decode('utf-8'))
                for value in values:
                    dump += f"\n{key}/{value}"
        return dump

    # save keystore to file
    @staticmethod
    def save(filename):
        Utils.writeFile(KeyStore.dump(), filename)
        return

    # load keystore from file
    @staticmethod
    def load(filename):
        lines = Utils.readFile(filename)
        for line in lines:
            KeyStore.add(line)
        return


# -----------------------------------------------------------------------------
# main test code
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    print("-------------------------------------------------------------------")
    #    KeyStore.add("host/1.2.3.4/port/111")
    #    KeyStore.add("host/a.b.c.d/port/80")
    #    KeyStore.add("host/a.b.c.d/port/80/bob")
    #    KeyStore.add("host/a.b.c.d/port/80/apple")
    #    KeyStore.add("host/a.b.c.d/port")
    #    KeyStore.add("host/a.b.c.d/port/443")
    KeyStore.add("host/1.1.1.1/port/80")
    KeyStore.add("host/1.1.1.1/port/8080")
    KeyStore.add("host/2.2.2.2/port/443")
    KeyStore.add("host/2.2.2.2/port/80")
    KeyStore.add("host/3.3.3.3/port/22")
    KeyStore.add("host/4.4.4.4/port/25")
    print("-------------------------------------------------------------------")
    # KeyStore.debug()
    # print KeyStore.dump()

    print(KeyStore.get("host/*/port/80"))
    print(KeyStore.get("host/2.2.2./port", "host/1.1.1.1/port"))
    # print KeyStore.get("host")
#    KeyStore.add("service/http/host/1.1.1.1/tcpport/80/product/apache/version/1.1.1.1.1.1.1")
#    KeyStore.add("service/http/host/1.1.1.1/tcpport/8080/product/apache/version/1.1.1.3.3.3.3")
#    KeyStore.add("service/https/host/2.2.2.2/tcpport/443/product/nginx/version/a.b.c.d")
#    KeyStore.add("service/http/host/2.2.2.2/tcpport/80/product/nginx/version/a.b.c.d")
#    KeyStore.add("service/ssh/host/3.3.3.3/tcpport/22/product/openssh/version/q.w.e")
#    KeyStore.add("service/smtp/host/4.4.4.4/tcpport/25/product/sendmail/version/9.8.7.6")
#    print "-------------------------------------------------------------------"
#    KeyStore.debug()

#    print KeyStore.get("service")
