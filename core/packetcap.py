from multiprocessing.pool import ThreadPool

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sniff


class PktCapture:

    @staticmethod
    def capture(filter_str="", timeout=60, count=1, srcip="", dstip=""):
        results = "Packet Capture  of (%s -> %s) filter (%s)\n\n" % (srcip, dstip, filter_str)
        packets = sniff(filter=filter_str, timeout=timeout, count=count)
        for pkt in packets:
            ip_src = ""
            ip_dst = ""
            # tcp_sport = 0
            # tcp_dport = 0
            tcp_payload = ""
            if IP in pkt:
                ip_src = str(pkt[IP].src)
                ip_dst = str(pkt[IP].dst)
            if TCP in pkt:
                # tcp_sport = int(pkt[TCP].sport)
                # tcp_dport = int(pkt[TCP].dport)
                tcp_payload = str(pkt[TCP].payload)

            if not tcp_payload.strip():
                continue

            if (srcip != "" or dstip != "") and srcip == "" and (ip_dst == dstip) or (srcip != "" or dstip != "") \
                    and srcip != "" and (ip_src == srcip):
                results += f">>>> {tcp_payload}\n"
            elif (srcip != "" or dstip != "") and srcip == "" or srcip != "":
                results += f"<<<< {tcp_payload}\n"
            else:
                results += f">><< {tcp_payload}\n"
        return results


# -----------------------------------------------------------------------------
# main test code
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    filter_str = "(host 192.168.1.8 or host 192.168.124) and tcp and port 21"
    pkt_count = 20
    pkt_timeout = 50
    srcip = "192.168.1.124"
    dstip = "192.168.1.8"

    pool = ThreadPool(processes=1)

    p = PktCapture()

    #    print p.capture(filter=filter_str, timeout=pkt_timeout, count=pkt_count, srcip=srcip, dstip=dstip)
    # tuple of args for foo, please note a "," at the end of the arguments
    async_result = pool.apply_async(p.capture, (filter_str, pkt_timeout, pkt_count, srcip, dstip,))

    # Do some other stuff in the main process
    print("hi")

    print(async_result.get())
