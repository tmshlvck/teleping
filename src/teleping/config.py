
# coding: utf-8
"""
Telephant Ping config module

Copyright (C) 2021-2024 Tomas Hlavacek (tmshlvck@gmail.com)

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
from functools import cached_property
from pydantic import BaseModel, computed_field, field_validator
from typing import List, Dict, Optional, Iterator
from ipaddress import IPv4Address, IPv6Address, ip_address
from yaml import load, SafeLoader
import socket

def resolve_host(host: str, afi: int|None =None) -> Iterator[IPv4Address|IPv6Address]:
    if afi == None:
        afi = [4, 6]
    else:
        afi = [afi,]
    
    for testafi in afi:
        try:
            for family, type, proto, canonname, sockaddr in socket.getaddrinfo(host, None, socket.AF_INET if testafi == 4 else socket.AF_INET6):
                yield ip_address(sockaddr[0])
        except socket.gaierror:
            logging.info(f"Ignoring host that can not be resolved: {host=} {afi=}")


class Target(BaseModel):
    host: str
    afi: int
    name: str

class NormalizedTarget(Target, frozen=True):
    addr: IPv4Address|IPv6Address

class UDPPingConfig(BaseModel):
    bind_address4: Optional[str] = None # this must be IPv4 address; i.e. 0.0.0.0
    bind_address6: Optional[str] = None # this must be IPv6 address; i.e. ::
    port: int
    interval: float

    #@field_validator('bind_address')
    #@classmethod
    #def convert2v6(cls, v: str) -> str:
    #    ip = ip_address(v.strip())
    #    if ip.version == 6:
    #        return str(ip)
    #    else:
    #        return str(ip_address('::ffff:' + v.strip()))
        

class HTTPServerConfig(BaseModel):
    enabled: Optional[bool] = True
    listen: str
    port: int

class Config(BaseModel):
    log_file: Optional[str] = None
    debug: Optional[bool] = False
    targets: Optional[List[Target]] = []
    udpping: UDPPingConfig
    control: HTTPServerConfig

    @computed_field
    @cached_property
    def normalized_targets(self) -> List[NormalizedTarget]:
        nt = set()
        for t in self.targets:
            try:
                a = ip_address(t.host)
                if a.version == t.afi:
                    nt.add(NormalizedTarget(**(t.model_dump()), addr=a))
                    continue
                else:
                    logging.info(f"Ignoring AFI mismatch in configuration: host={t.host} afi={t.afi}")
            except:
                pass
            
            for a in resolve_host(t.host, t.afi):
                nt.add(NormalizedTarget(**t.model_dump(), addr=a))
        
        return list(nt)
    
#    @computed_field
#    @cached_property
#    def normalized_targets_by_ip(self) -> Dict[str,NormalizedTarget]:
#        return {str(t.addr): t for t in self.normalized_targets}

def read_config(filename: str):
    with open(filename, 'r') as fh:
        ycf = load(fh.read(), Loader=SafeLoader)
        return Config(**ycf)

