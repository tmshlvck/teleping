# coding: utf-8
"""
Telephant Ping common module

Copyright (C) 2021-2023 Tomas Hlavacek (tmshlvck@gmail.com)

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

import logging
import subprocess
import shutil
import traceback
import json
import ipaddress


from typing import Any, Dict, List, Tuple, Set, Iterator
from ipaddress import IPv4Address, IPv6Address, ip_address


def run_linux_cmd(cmd: List[str]) -> Dict[str, str|int]:
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        return {'cmd': ' '.join(cmd), 'return_code': process.returncode, 'stdout': stdout.decode().strip(), 'stderr' : stderr.decode().strip()}
    except Exception as e:
        return {'cmd': ' '.join(cmd), 'exception': traceback.format_exc()}

BIN_IP = shutil.which('ip')
def run_ip_link(bin_ip:str =BIN_IP) -> Dict[str, str|int]:
    cmd = [bin_ip, '-s', 'link']
    return run_linux_cmd(cmd)

def run_ip_address(bin_ip: str =BIN_IP) -> Dict[str, str|int]:
    cmd = [bin_ip, 'address']
    return run_linux_cmd(cmd)

def run_ip_address_parse(bin_ip:str =BIN_IP) -> List[str]:
    cmd = [bin_ip, '-j', 'address']
    res = run_linux_cmd(cmd)
    parsed_res = json.loads(res['stdout'])
    hostaddrs = set()
    for iface in parsed_res:
        for ai in iface.get('addr_info',[]):
            a = ai.get('local', None)
            ipa = ipaddress.ip_address(a)
            if ipa.is_loopback:
                pass
            else:
                hostaddrs.add(a)
    return list(hostaddrs)

def run_ip_route(afi: int =4, bin_ip: str =BIN_IP) -> Dict[str, str|int]:
    if afi == 4:
        cmd = [bin_ip, 'route']
    elif afi == 6:
        cmd = [bin_ip, '-6', 'route']
    return run_linux_cmd(cmd)

BIN_PING = shutil.which('ping')
def run_linux_ping(host: str, count: int =10, timeout_sec: int =4, packet_size: int =64, interval_sec: int =1, afi: int =4, bin_ping=BIN_PING) -> Dict[str, str|int]:
    cmd = [bin_ping, '-c', str(count), '-W', str(timeout_sec), '-s', str(packet_size), '-i', str(interval_sec), host]
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        return {'cmd': ' '.join(cmd), 'return_code': process.returncode, 'stdout': stdout.decode(), 'stderr' : stderr.decode()}
    except Exception as e:
        return {'cmd': ' '.join(cmd), 'exception': traceback.format_exc()}

BIN_TRACEROUTE = shutil.which('traceroute')
BIN_TRACEROUTE6 = shutil.which('traceroute6')
def run_linux_traceroute(target: str, afi: int =4, max_hops: int =30, wait_sec: int =5, bin_traceroute=BIN_TRACEROUTE, bin_traceroute6=BIN_TRACEROUTE6) -> Tuple[Dict[str,Any], Set[ipaddress.IPv4Address|ipaddress.IPv6Address]]:
    try:
        if afi == 4:
            cmd = [bin_traceroute, '-m', str(max_hops), '-w', str(wait_sec), target]
        elif afi == 6:
            cmd = [bin_traceroute6, '-m', str(max_hops), '-w', str(wait_sec), target]
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

