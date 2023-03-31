import asyncio
import datetime
import threading
import os
import pefile
import psutil
import pyshark
import netifaces
import sys
import subprocess
import win32evtlog
import time

argv = sys.argv
print("""

▓█████ ▒██   ██▒▄▄▄█████▓ ██▀███   ▄▄▄       ▄████▄  ▄▄▄█████▓ ▒█████   ██▀███  
▓█   ▀ ▒▒ █ █ ▒░▓  ██▒ ▓▒▓██ ▒ ██▒▒████▄    ▒██▀ ▀█  ▓  ██▒ ▓▒▒██▒  ██▒▓██ ▒ ██▒
▒███   ░░  █   ░▒ ▓██░ ▒░▓██ ░▄█ ▒▒██  ▀█▄  ▒▓█    ▄ ▒ ▓██░ ▒░▒██░  ██▒▓██ ░▄█ ▒
▒▓█  ▄  ░ █ █ ▒ ░ ▓██▓ ░ ▒██▀▀█▄  ░██▄▄▄▄██ ▒▓▓▄ ▄██▒░ ▓██▓ ░ ▒██   ██░▒██▀▀█▄  
░▒████▒▒██▒ ▒██▒  ▒██▒ ░ ░██▓ ▒██▒ ▓█   ▓██▒▒ ▓███▀ ░  ▒██▒ ░ ░ ████▓▒░░██▓ ▒██▒
░░ ▒░ ░▒▒ ░ ░▓ ░  ▒ ░░   ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░░ ░▒ ▒  ░  ▒ ░░   ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░
 ░ ░  ░░░   ░▒ ░    ░      ░▒ ░ ▒░  ▒   ▒▒ ░  ░  ▒       ░      ░ ▒ ▒░   ░▒ ░ ▒░
   ░    ░    ░    ░        ░░   ░   ░   ▒   ░          ░      ░ ░ ░ ▒    ░░   ░ 
   ░  ░ ░    ░              ░           ░  ░░ ░                   ░ ░     ░     
                                            ░                                   
                    Yazidou - http://www.github.com/Xacone
""")

os.system("wevtutil sl Microsoft-Windows-TaskScheduler/Operational /enabled:true")

captured_csv = "time,ip_version,src_ip,src_port,dst_ip,dst_port,ip_ttl,proto,ip_flags\n"

def packet_capture_for_specific_pid(pid, interface):
    print(f"[*] Laucnhing packet capture on {interface}")

    global t_hdr, captured_csv, connections

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    process = psutil.Process(pid)
    if process:
        connections = process.connections()
    if not connections:
        print(f"Aucun process avec le PID :  {pid} sur le réseau.")
        return

    # Choose the first network interface used by the process
    local = connections[0].laddr
    remote = connections[0].raddr

    cap_filter = ""
    i = 0
    for conn in connections:
        i += 1
        cap_filter += "(tcp src port " + str(conn.laddr.port) + " and tcp dst port " + str(conn.raddr.port) + ")"
        if i != len(connections):
            cap_filter += " or "
    global capture
    try:
        capture = pyshark.LiveCapture(interface=interface, bpf_filter=cap_filter)
        for packet in capture.sniff_continuously():
            if 'IP' in packet:
                if 'TCP' in packet:
                    t_hdr = packet['TCP']
                elif 'UDP' in packet:
                    t_hdr = packet['UDP']
                now = datetime.datetime.now()
                whattimeisit = now.strftime("%H:%M:%S")
                captured = f"{whattimeisit},{packet.ip.version},{packet.ip.src},{t_hdr.srcport},{packet.ip.dst},{t_hdr.dstport},{packet.ip.ttl},{packet.ip.proto},{packet.ip.flags}\n"
                captured_csv = captured_csv + captured
                print(captured_csv)
    except pyshark.capture.live_capture.UnknownInterfaceException as e:
        print("")


def launch_packet_capture(pid):
    threads = []

    interfaces = netifaces.interfaces()
    for intf in interfaces:
        int_name = "\\Device\\NPF_" + intf
        t = threading.Thread(target=packet_capture_for_specific_pid, args=(pid, int_name,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

def DLL_and_Functions_Extractor(path):
    pe = pefile.PE(path)
    imported = "<Header>\n"
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        # print("Imported DLL:", entry.dll.decode())
        imported = imported + "\t<DLL name=\"" + entry.dll.decode() + "\">\n"
        for imp in entry.imports:
            if (imp.name):
                imported += "\t\t<Function>" + imp.name.decode() + "</Function>\n"
            else:
                imported += "\t\t<Ordinal>" + hex(imp.ordinal) + "</Function>\n"
        imported = imported + "\t</DLL>\n"
    imported = imported + "</Header>"
    print(imported)

def launch_process(path):
    DLL_and_Functions_Extractor(path)
    process = subprocess.Popen(path)
    pid = process.pid
    print("[*] Binded to process with PID : " + str(pid))
    launch_packet_capture(pid)

def EventViewerExtractor():
    journal = 0
    i = 0
    h = win32evtlog.EvtOpenChannelEnum(None)
    while win32evtlog.EvtNextChannelPath(h) is not None:
        try:
            channelName = win32evtlog.EvtNextChannelPath(h)
            print("[*] Processed : " + channelName)
            flags = win32evtlog.EvtQueryReverseDirection
            evtQuery = "*"
            evtQueryTimeout = -1
            evtQueryResult = win32evtlog.EvtQuery(channelName, flags, evtQuery, None)
            evtQueryResultNo = 1000
            events = win32evtlog.EvtNext(evtQueryResult, evtQueryResultNo, evtQueryTimeout, 0)
            for event in events:
                    i += 1
                    if win32evtlog.EvtNextChannelPath(h) is not None:
                        file_name = win32evtlog.EvtNextChannelPath(h) + ".xml"
                        file_name = file_name.replace(" ", "_")
                        file_name = file_name.replace("/", "_")

                        print(i," - ",win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml) + "\n\n\ns")

                        dir_name = "OBSV_XML"
                        if not os.path.exists("OBSV_XML"):
                            os.mkdir("OBSV_XML")
                        """
                        f = open(dir_name + "/" + file_name, "w")
                        f.write(win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml))
                        f.close()
                        """

        except Exception as e:
            print("Erreur avec : ", win32evtlog.EvtNextChannelPath(h))
            print(e)
            """
            if win32evtlog.EvtNextChannelPath(h) is not None:
                print("[!] Incomplete data for : " + win32evtlog.EvtNextChannelPath(h))
            """
    journal += 1

EventViewerExtractor()
launch_process(argv[1])
