import asyncio
import datetime
import json
import threading
import os
import pefile
import psutil
import pyshark
import netifaces
import sys
import subprocess
import requests
import win32evtlog
import time
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver import ActionChains
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC, wait

argv = sys.argv
print("""
 ▄▄▄·▄▄▄         ▄▄· ▄▄▄ ..▄▄ · .▄▄ ·     ▄▄▄ .▐▄• ▄ ▄▄▄▄▄▄▄▄   ▄▄▄·  ▄▄· ▄▄▄▄▄      ▄▄▄  
▐█ ▄█▀▄ █·▪     ▐█ ▌▪▀▄.▀·▐█ ▀. ▐█ ▀.     ▀▄.▀· █▌█▌▪•██  ▀▄ █·▐█ ▀█ ▐█ ▌▪•██  ▪     ▀▄ █·
 ██▀·▐▀▀▄  ▄█▀▄ ██ ▄▄▐▀▀▪▄▄▀▀▀█▄▄▀▀▀█▄    ▐▀▀▪▄ ·██·  ▐█.▪▐▀▀▄ ▄█▀▀█ ██ ▄▄ ▐█.▪ ▄█▀▄ ▐▀▀▄ 
▐█▪·•▐█•█▌▐█▌.▐▌▐███▌▐█▄▄▌▐█▄▪▐█▐█▄▪▐█    ▐█▄▄▌▪▐█·█▌ ▐█▌·▐█•█▌▐█ ▪▐▌▐███▌ ▐█▌·▐█▌.▐▌▐█•█▌
.▀   .▀  ▀ ▀█▄▀▪·▀▀▀  ▀▀▀  ▀▀▀▀  ▀▀▀▀      ▀▀▀ •▀▀ ▀▀ ▀▀▀ .▀  ▀ ▀  ▀ ·▀▀▀  ▀▀▀  ▀█▄▀▪.▀  ▀
                     Yazid - http://www.github.com/Xacone
""")

os.system("wevtutil sl Microsoft-Windows-TaskScheduler/Operational /enabled:true")
captured_csv = "time,ip_version,src_ip,src_port,dst_ip,dst_port,ip_ttl,proto,ip_flags\n"
functionsValuesForMsftParsing = []
launchedMsftParsingThreads = []


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
            if imp.name:
                imported += "\t\t<Function>" + imp.name.decode() + "</Function>\n"
                # Exclusion of debug-time libraries
                if entry.dll.decode() != "MSVCP140D.dll" and entry.dll.decode() != "ucrtbased.dll" and entry.dll.decode() != "VCRUNTIME140_1D.dll" and entry.dll.decode() != "VCRUNTIME140D.dll":
                    functionsValuesForMsftParsing.append(imp.name.decode())
            else:
                imported += "\t\t<Ordinal>" + hex(imp.ordinal) + "</Function>\n"
        imported = imported + "\t</DLL>\n"
    imported = imported + "</Header>"
    print(imported)


def EventViewerExtractor():
    concated = "<EventViewerDump>\n"
    journal = 0
    i = 0
    h = win32evtlog.EvtOpenChannelEnum(None)
    server = 'localhost'
    # chann = win32evtlog.EvtNextChannelPath(h)
    chann = "Microsoft-Windows-TaskScheduler/Operational"
    while chann is not None:
        i += 1
        handler = win32evtlog.OpenEventLog(server, chann)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        total = win32evtlog.GetNumberOfEventLogRecords(handler)
        while True:
            events = win32evtlog.ReadEventLog(handler, flags, 0)
            if events:
                for event in events:
                    concated += "\t<Event>\n"
                    i += 1

                    cat = "\t\t<Category>" + str(event.EventCategory) + "</Category>"
                    time_gen = "\t\t<Time>" + str(event.TimeGenerated) + "</Time>"
                    src_name = "\t\t<Source>" + str(event.SourceName) + "</Source>"
                    event_id = "\t\t<EventID>" + str(event.EventID) + "</EventID>"
                    event_type = "\t\t<EventType>" + str(event.EventCategory) + "</EventType>"

                    concated += cat + "\n" + time_gen + "\n" + src_name + "\n" + event_id + "\n" + event_type + "\n"
                    concated += "\t\t<EventData>\n"

                    data = event.StringInserts
                    if data:
                        for msg in data:
                            concated += msg
                            concated += "\n"

                    concated + "\n"
                    concated += "\t\t</EventData>\n"
                    concated += "\t</Event>\n"

                    if i >= 6000:
                        concated += "</EventViewerDump>"
                        return concated

    return concated


def VirusTotalAPIContent(key, target):
    # https://www.virustotal.com/old-browsers/file/ + ....

    url = 'https://www.virustotal.com/vtapi/v2/file/scan'

    params = {'apikey': key}
    with open(target, 'rb') as file:

        response = requests.post(url, params=params, files={'file': file})
        time.sleep(15)

        if response.status_code == 200:

            print("\n[VirusTotal] File successfully uploaded.")
            print("[VirusTotal] Processing file...")

            print(response.content)
            parsed_data = json.loads(response.content)
            print("\n[VirusTotal] Parsing ", parsed_data["permalink"])

            scan_id = parsed_data["resource"]
            req_url = "https://www.virustotal.com/old-browsers/file/" + scan_id
            print("URL : " + req_url)

            options = webdriver.ChromeOptions()
            options.add_argument('headless')
            driver = webdriver.Chrome(options=options)
            driver.get(req_url)
            html_content = driver.page_source

            soup = BeautifulSoup(html_content, "html.parser")
            # tr_div = soup.find("tr")
            td_div = soup.findAll("td")
            # print(td_div)
            concated = "<SecurityVendors>\n"
            for i in range(0, len(td_div) - 3, 3):
                concated += "\t<Vendor>\n"
                concated += "\t\t<Logo>https://api.kickfire.com/logo?website=" + td_div[i].text + ".com</Logo>\n"
                concated += "\t\t<Name>" + td_div[i].text + "</Name>\n"
                i += 1
                result = "No"
                if td_div[i].text == "malicious":
                    result = "Yes"
                concated += "\t\t<Detected>" + result + "</Detected>\n"
                i += 1
                concated += "\t\t<Update>" + td_div[i].text + "</Update>\n"
                concated += "\t</Vendor>\n"
            concated += "</SecurityVendors>"
            return concated
        else:
            print("\n[VirusTotal] Error while uploading file.")


options = webdriver.ChromeOptions()
options.add_argument('headless')
options.add_argument('disable-gpu')
# driver = webdriver.Chrome(options=options)
driver = webdriver.Chrome()

# driver.get('https://learn.microsoft.com/fr-fr/search/?terms=' + functionName)
driver.get('https://learn.microsoft.com/fr-fr/search/')


def MicrosoftSingleAPIContent(functionName):
    concated = "\t<ResolvedFunction>\n"
    # driver.get('https://learn.microsoft.com/en-us/search/')

    # search_bar = wait.until(EC.visibility_of_element_located((By.ID, 'facet-search-input')))
    search_bar = WebDriverWait(driver, 15).until(EC.presence_of_element_located((By.ID, "facet-search-input")))
    search_bar.send_keys(functionName)
    search_bar.send_keys(Keys.RETURN)

    time.sleep(0.3)  # <-------

    ActionChains(driver).key_down(Keys.CONTROL).send_keys('a').key_up(Keys.CONTROL).perform()
    search_bar.send_keys(Keys.DELETE)

    try:
        html = driver.page_source
        soup = BeautifulSoup(html, 'html.parser')
        first_result_title = soup.find_all('a', attrs={"data-bi-name": "searchItem.0"})
        if first_result_title:
            title_text = first_result_title[0].text
            concated += "\t\t<Title>" + title_text + "</Title>\n"
            title_link = first_result_title[0]["href"]
            concated += "\t\t<Link>" + title_link + "</Link>\n"
        concated += "\t</ResolvedFunction>\n"
        return concated
    except:
        print("Toz")
        return


# TODO
# def WhoisContent() ?

# TODO
# def ip_addr_info()

def launch_process(path, key):
    if path and key:

        """ OK
        virus_total_xml = VirusTotalAPIContent(key, path)
        with open("VirusTotalContent.xml", "w", encoding='utf-8') as file:
            file.write(virus_total_xml)
        """

        launched_microsoft_parsing_threads = []
        DLL_and_Functions_Extractor(path)
        # MicrosoftSingleAPIContent("CreateEventW")

        final_val = "<MicrosoftAPIParsing>\n"
        for value in functionsValuesForMsftParsing:
            final_val += MicrosoftSingleAPIContent(value)
        final_val += "</MicrosoftAPIParsing>\n"
        with open("MicrosoftAPIParsing.xml", "w", encoding='utf-8') as file:
            file.write(final_val)

        driver.quit()

        """ OK
        event_viewer_xml = EventViewerExtractor()
        with open("EventViewerContent.xml", "w", encoding='utf-8') as file:
            file.write(event_viewer_xml)
        """

        """
        process = subprocess.Popen(path)
        pid = process.pid
        print("[*] Binded to process with PID : " + str(pid))
        # launch_packet_capture(pid)
        """
    else:
        print("Arguments manquants")


launch_process(argv[1], argv[2])

"""
for value in functionsValuesForMsftParsing:
    MicrosoftSingleAPIContent(value)
"""

# MicrosoftSingleAPIContent("WSAStartup")
