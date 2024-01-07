# coding: utf-8
"""
Telephant basic module

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

import subprocess
import shutil
import traceback
import json
import ipaddress

def run_linux_cmd(cmd):
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        return {'cmd': ' '.join(cmd), 'return_code': process.returncode, 'stdout': stdout.decode().strip(), 'stderr' : stderr.decode().strip()}
    except Exception as e:
        return {'cmd': ' '.join(cmd), 'exception': traceback.format_exc()}

BIN_IP = shutil.which('ip')
def ip_link(config):
    cmd = [config.get('bin_ip', BIN_IP), '-s', 'link']
    return run_linux_cmd(cmd)

def ip_address(config):
    cmd = [config.get('bin_ip', BIN_IP), 'address']
    return run_linux_cmd(cmd)

def ip_address_parse(config):
    cmd = [config.get('bin_ip', BIN_IP), '-j', 'address']
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

def ip_route(config, afi: int =4):
    if afi == 4:
        cmd = [config.get('bin_ip', BIN_IP), 'route']
    elif afi == 6:
        cmd = [config.get('bin_ip', BIN_IP), '-6', 'route']
    return run_linux_cmd(cmd)
