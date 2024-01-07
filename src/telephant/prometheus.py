# coding: utf-8
"""
UDPDrill
Based on The UDP Smoke - fast UDP ping that gathers statistics

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

PAYLOAD_LEN = 100
TIMEOUT = 10 # sec
SCRAPE_INTERVAL = 15 # sec - this is the expected Prometheus scrape interval, but the RTT sliding window average uses it as well
PROMETHEUS_SERVER_LISTEN="::"
PROMETHEUS_SERVER_PORT=8888


import logging
import time
import struct
import warnings
import ipaddress
import curses
import math
import socket
import threading
import socketserver
import http
import http.server
import sys

# Prometheus minimalistic server

class Counter:
  def __init__(self, name, value, labels):
    self.name = name
    self.value = value
    self.labels = labels

  def render(self, namespace):
    mn = f"{namespace}_{self.name}"
    ret = ''
    # help
    ret += f"# HELP {mn} metric {self.name}\n"
    ret += f"# TYPE {mn} counter\n"

    rlabels = ''
    for l in self.labels:
      if rlabels:
        rlabels+=','
      rlabels += f'{l}="{self.labels[l]}"'
    ret += f'{mn}{{{rlabels}}} {self.value}\n'

    return ret.encode()


class Summary:
  def __init__(self, name, summ, count, labels, quantiles=None):
    self.name = name
    self.summ = summ
    self.count = count
    self.labels = labels
    self.quantiles = quantiles

  def render(self, namespace):
    mn = f"{namespace}_{self.name}"
    ret = ''
    # help
    ret += f"# HELP {mn} metric {self.name}\n"
    ret += f"# TYPE {mn} summary\n"

    rlabels = ''
    for l in self.labels:
      if rlabels:
        rlabels+=','
      rlabels += f'{l}="{self.labels[l]}"'

    if self.quantiles:
      for q,v in self.quantiles:
        ret += f'{mn}{{quantile="{q}",{rlabels}}} {v}\n'

    ret += f'{mn}_sum{{{rlabels}}} {self.summ}\n'
    ret += f'{mn}_count{{{rlabels}}} {self.count}\n'

    return ret.encode()

