# coding: utf-8
"""
Telephant Traceroute

Copyright (C) 2023 Tomas Hlavacek (tmshlvck@gmail.com)

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.
This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses/>.
"""

########## Very basic experimental Python traceroute(6) prototype ##########

import socket
import datetime
import struct

def python_tracert_steps(config, tgt: str, afi=4, max_hops=30, wait_sec=5):
    dest_addr = socket.getaddrinfo(tgt, None, socket.AF_INET if afi==4 else socket.AF_INET6)[0][4][0]
    print(f"Target address: {dest_addr}")
    proto_icmp = socket.getprotobyname("icmp") if afi==4 else socket.getprotobyname("ipv6-icmp")
    print(f"Recv proto: {proto_icmp}")
    proto_udp = socket.getprotobyname("udp")
    print(f"Send proto: {proto_udp}")
    port = 33434

    for ttl in range(1, max_hops + 1):
        rx = socket.socket(socket.AF_INET if afi==4 else socket.AF_INET6, socket.SOCK_RAW, proto_icmp)
        rx.settimeout(wait_sec)

        rx.bind(("", port))
        tx = socket.socket(socket.AF_INET if afi==4 else socket.AF_INET6, socket.SOCK_DGRAM, proto_udp)
        if afi == 4:
            tx.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        
            start = datetime.datetime.now()
            tx.sendto("".encode(), (dest_addr, port))
        else:
            #tx.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)

            start = datetime.datetime.now()
            tx.sendmsg("".encode(), [(socket.IPPROTO_IPV6, socket.IPV6_HOPLIMIT, struct.pack("i",ttl))],0, (dest_addr, port))

        try:
            _, curr_addr = rx.recvfrom(512)
            curr_addr = curr_addr[0]
        except socket.error:
            curr_addr = "*"
        finally:
            end = datetime.datetime.now()
            rx.close()
            tx.close()

        yield (curr_addr, (end - start).microseconds)

        if curr_addr == dest_addr:
            break

def python_traceroute(config, tgt: str, afi=4, max_hops=30, wait_sec=5):
    result = ''
    for addr, rtt in python_tracert_steps(config, tgt, afi, max_hops, wait_sec):
        result += f"{addr} : {str(rtt)} us\n"
    return {'result': result}

########## End of Prototype ##########

import subprocess
import shutil
import traceback
import ipaddress
from typing import Tuple,Dict,Set,Any

BIN_TRACEROUTE = shutil.which('traceroute')
BIN_TRACEROUTE6 = shutil.which('traceroute6')

def linux_traceroute(config, target: str, afi: int =4, max_hops: int =30, wait_sec: int =5) -> Tuple[Dict[str,Any], Set[ipaddress.IPv4Address|ipaddress.IPv6Address]]:
    try:
        if afi == 4:
            cmd = [config.get('bin_traceroute', BIN_TRACEROUTE), '-m', str(max_hops), '-w', str(wait_sec), target]
        elif afi == 6:
            cmd = [config.get('bin_traceroute6', BIN_TRACEROUTE6), '-m', str(max_hops), '-w', str(wait_sec), target]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        hipas = set()
        for l in stdout.decode().splitlines():
            for e in l.split():
                e = e.strip()
                if '(' in e and ')' in e:
                    e = e.lstrip('(').rstrip(')').strip()
                    try:
                        hipas.add(ipaddress.ip_address(e))
                    except:
                        pass


        return ({'cmd': ' '.join(cmd), 'return_code': process.returncode, 'stdout': stdout.decode(), 'stderr' : stderr.decode()}, hipas)
    except Exception as e:
        return {'cmd': ' '.join(cmd) ,'exception': traceback.format_exc()}, set()
