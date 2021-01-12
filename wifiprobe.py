#!/usr/bin/env python3
from scapy.all import *
from datetime import datetime

from netaddr import EUI
from netaddr.core import NotRegisteredError

import time
import requests
import json
import pprint

sensor_id = 3 

# url = 'https://xxx.xxx.xxx.xxx/yyy/area/3'
url = 'https://localhost/area/3' % (sensor_id)
h = {'Content-type': 'application/json'}
wifidev = "wlan1"

mac_list = []
black_list = ['b8:27:eb:xx:xx:xx']
start = int(time.time())

def debug_macaddr(pkt):
    # print ("\t %s Client: %s probing for SSID: %s") % (time, pkt.addr2, pkt.info)
    macaddr = EUI(pkt.addr2)
    try:
        print (macaddr.oui.registration().org, pkt.addr2)
    except NotRegisteredError:
        print ("Not Resisterd:", pkt.addr2)

def PacketHandler(pkt) :
    global mac_list
    global start

    if pkt.haslayer(Dot11ProbeReq):
 
        ctime = time.time()
        td = ctime - start

        # 1分ごとのWiFi Probe Request数
        if(td > 60):  
            start = int(ctime)-int(ctime)%60
            unixtime = int(ctime*1000)
            p = json.dumps({str(unixtime):{"id":sensor_id, "data":len(mac_list)}})
            # print (ctime, p)
            try: 
              req = requests.post(url, p, headers=h, timeout=(10.0,30.0))
            except ConnectionError as e:
              print(e)
            except Exception as e:
              print('unknown exception!')
              print(e) 
            else:
              if req.status_code == requests.codes.ok:
                pprint.pprint(req.json())
              else:
                print("404 not found.")
 
            del mac_list[:]

        # Probe Request
        if pkt.type == 0 and pkt.subtype == 4 :
            if pkt.addr2 not in mac_list and pkt.addr2 not in black_list:
                mac_list.append(pkt.addr2)
                # debug_macaddr(pkt)

while True:
  try:
    sniff(iface=wifidev, prn = PacketHandler, count=0, store=0, timeout=5)
  except Exception as e:
    print ("Sniff Error: ", e)
  finally:
     time.sleep(1)
