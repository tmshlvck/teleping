# coding: utf-8
"""
Telephant Ping

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

########## Very basic experimental Python ping prototype ##########
import socket
import struct
import select
import time
import datetime

def calculate_checksum(packet: bytes):
    checksum = 0
    for i in range(0, len(packet), 2):
        chunk = packet[i:i+2]
        chunk_value = int.from_bytes(chunk, "big")
        checksum += chunk_value
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += (checksum >> 16)
    checksum = ~checksum & 0xffff
    return checksum

ICMP_TYPE_ECHO_REQUEST = 8
ICMPv6_TYPE_ECHO_REQUEST = 128

ICMP_IDENTIFIER = 0x7e1e

def create_packet(icmp_sequence_number, afi):
    icmp_type = ICMP_TYPE_ECHO_REQUEST if afi == 4 else ICMPv6_TYPE_ECHO_REQUEST
    icmp_code = 0
    icmp_checksum = 0
    data = b""
    packet = struct.pack("!2B3H", icmp_type, icmp_code, icmp_checksum, ICMP_IDENTIFIER, icmp_sequence_number) + data
    checksum = calculate_checksum(packet)
    packet = packet[:2] + struct.pack("!H", checksum) + packet[4:]
    return packet

def parse_packet(data, afi):
    if afi == 4:
        offset = 20
    if afi == 6:
        offset = 0
    
    icmp_type, icmp_code, icmp_checksum, icmp_identifier, icmp_sequence_number = struct.unpack("!2B3H", data[offset:offset+8])

    if icmp_identifier != ICMP_IDENTIFIER:
        raise ValueError(f"Unexpected icmp identifier: {icmp_identifier}")

    if afi == 4:
        if icmp_type != 0:
            raise ValueError(f"Unexpected icmp type {icmp_type}")
    if afi == 6:
        if icmp_type != 129:
            raise ValueError(f"Unexpected icmpv6 type {icmp_type}")
    
    return (icmp_type, icmp_code, icmp_checksum, icmp_identifier, icmp_sequence_number)

def one_ping(host: str, icmp_sequence_number: int, timeout: int =1, packet_size: int =64, afi: int =4) -> int:
    out = ''
    try:
        if afi == 4:
            icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        else:
            icmp_socket = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
        icmp_socket.settimeout(timeout)
        packet = create_packet(icmp_sequence_number, afi)
        icmp_socket.sendto(packet, (host, 0))
        start = datetime.datetime.now()

        while timeout > 0:
            ready, _, _ = select.select([icmp_socket], [], [], timeout)
            if ready:
                pckt, address = icmp_socket.recvfrom(packet_size)
                elapsed = (datetime.datetime.now() - start).microseconds

                try:
                    recv_icmp_type, recv_icmp_code, recv_icmp_checksum, recv_icmp_identifier, recv_icmp_sequence_number = parse_packet(pckt, afi)
                except:
                    out += f"parsing exception: {pckt}\n"
                    timeout -= elapsed
                    continue

                if icmp_sequence_number != recv_icmp_sequence_number:
                    out += f"recv wrong seqnump from {address} icmp_type={recv_icmp_type} icmp_code={recv_icmp_code} icmp_checksum={recv_icmp_checksum} icmp_identifier={recv_icmp_identifier} icmp_sequence_number={icmp_sequence_number}\n"
                    continue
                
                out += f"recv from {address} icmp_type={recv_icmp_type} icmp_code={recv_icmp_code} icmp_checksum={recv_icmp_checksum} icmp_identifier={recv_icmp_identifier} icmp_sequence_number={icmp_sequence_number}\n"
                return (elapsed, out)
            else:
                return (None, '')
    except socket.error as e:
        out += f"socket.error: {str(e)}\n"
        return (None, '')
    finally:
        icmp_socket.close()

def python_ping(config, host: str, count: int =10, timeout_sec: int =1, packet_size: int =64, interval_sec: int =1, afi: int =4):
    out = ''
    for seq in range(0,count):
        rtt, out_add = one_ping(host, seq, timeou_sec, packet_size, afi)
        out += out_add
        if rtt:
            out += f"reply, rtt={rtt} us\n"
        else:
            out += f"timeout\n"
        time.sleep(interval_sec)
    return {'result': out}

########## End of Prototype ##########

import subprocess
import shutil
import traceback

BIN_PING = shutil.which('ping')
def linux_ping(config, host: str, count: int =10, timeout_sec: int =4, packet_size: int =64, interval_sec: int =1, afi: int =4):
    cmd = [config.get('bin_ping', BIN_PING), '-c', str(count), '-W', str(timeout_sec), '-s', str(packet_size), '-i', str(interval_sec), host]
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        return {'cmd': ' '.join(cmd), 'return_code': process.returncode, 'stdout': stdout.decode(), 'stderr' : stderr.decode()}
    except Exception as e:
        return {'cmd': ' '.join(cmd), 'exception': traceback.format_exc()}
