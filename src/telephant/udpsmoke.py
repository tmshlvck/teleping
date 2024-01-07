#!/usr/bin/env python3
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

   

# Actual UDPsmoke implementation

class SmokeProtocol:
  HEADER = struct.Struct('!cQI')
  PAYLOAD = ('*'*PAYLOAD_LEN).encode('ascii')

  PKT_TYPE_PING = b'p'
  PKT_TYPE_PONG = b'r'

  @classmethod
  def gen_ping(cls, pid):
    return cls.HEADER.pack(cls.PKT_TYPE_PING, pid, len(cls.PAYLOAD)) + cls.PAYLOAD


  @classmethod
  def decode_packet(cls, data):
    op, pid, plen = cls.HEADER.unpack_from(data)
    pl = data[cls.HEADER.size:]
    if len(pl) != plen:
      raise ValueError(f"Payload length {plen} differs from payload {len(pl)}.")
    return op, pid, pl


  @classmethod
  def gen_pong(cls, pid, pl):
    return cls.HEADER.pack(cls.PKT_TYPE_PONG, pid, len(pl)) + pl


  __slots__ = ['lock', 'ip', 'proto', 'name', 'lastsentpid', 'lastrcvdpid', 'pending', 'sent', 'received', 'lost', 'outoforder', 'rtt_sum', 'rtt_avg', 'rtt_var', 'win', 'interval', 'rtt_data']
  def __init__(self, lock, ip, interval, name=None, timeout=TIMEOUT):
    self.ip = ip
    self.proto = 4 if ipaddress.ip_address(ip).ipv4_mapped != None else 6
    self.name = name

    self.lock = lock
    self.lastsentpid = 0
    self.lastrcvdpid = 0
    self.pending = {}

    self.sent = 0
    self.received = 0
    self.lost = 0
    self.outoforder = 0
    self.rtt_sum = 0.0
    self.rtt_avg = 0.0
    self.rtt_var = 0.0

    self.win = int(SCRAPE_INTERVAL/interval)
    self.rtt_data = [None]*self.win


  def emit_ping(self):
    self.lock.acquire()
    
    self.lastsentpid+=1
    if self.lastsentpid > 2**63:
      self.lastsentpid = 1
    self.pending[self.lastsentpid] = time.perf_counter()
    self.sent += 1

    self.lock.release()

    return self.gen_ping(self.lastsentpid)


  def _updateRtt(self, rtt):
    self.rtt_sum += rtt
    self.rtt_data.append(rtt)
    oldestpoint = self.rtt_data.pop(0)

    if oldestpoint == None:
      self.rtt_avg = sum([x for x in self.rtt_data if x != None])/sum(1 for x in self.rtt_data if x != None)
      try:
        self.rtt_var = sum([(x-self.rtt_avg)**2 for x in self.rtt_data if x != None])/(sum(1 for x in self.rtt_data if x != None)-1)
      except:
        self.rtt_var = 0.0
    else:
      last_rtt_avg = self.rtt_avg
      self.rtt_avg += (rtt - oldestpoint)/self.win
      self.rtt_var += (rtt - oldestpoint)*(rtt - self.rtt_avg + oldestpoint - last_rtt_avg)/(self.win-1)
      if self.rtt_var < 0: # this can happen due to rounding errors
        self.rtt_var == 0.0


  def process_pong(self, pid):
    recv_t = time.perf_counter()

    self.lock.acquire()

    if pid in self.pending:
      self.received += 1
      rtt = 1000*(recv_t - self.pending[pid])
      self.pending.pop(pid)
      self._updateRtt(rtt)
      if self.lastrcvdpid < pid or pid == 1:
        pass
      else:
        self.outoforder += 1
      self.lastrcvdpid = pid
    else:
      pass # received packet that is not expected -> ignore

    self.lock.release()


  def _update_lost_unsafe(self):
    t = time.perf_counter()
    timedout = [pid for pid in self.pending if t > self.pending[pid]+TIMEOUT]
    for pid in timedout:
      self.lost += 1
      self.pending.pop(pid)


  def get_human_metrics(self):
    self.lock.acquire()
    self._update_lost_unsafe()
    ret = (self.sent, self.received, self.lost, self.outoforder, self.rtt_avg, self.rtt_var)
    self.lock.release()
    return ret


  def get_prometheus_metrics(self):
    self.lock.acquire()
    self._update_lost_unsafe()
    ret = [Counter('sent', self.sent, {'peerip':self.ip,'peer':self.name,'proto':self.proto}),
           Counter('received', self.received, {'peerip':self.ip,'peer':self.name,'proto':self.proto}),
           Counter('lost', self.lost, {'peerip':self.ip,'peer':self.name,'proto':self.proto}),
           Counter('outoforder', self.outoforder, {'peerip':self.ip,'peer':self.name,'proto':self.proto}),
           Summary('rtt', self.rtt_sum, self.received, {'peerip':self.ip,'peer':self.name,'proto':self.proto})]
    self.lock.release()
    return ret


class ThreadingSmokeProtocol(SmokeProtocol):
  def __init__(self, ip, interval, name=None, timeout=TIMEOUT):
    lock = threading.Lock()
    super().__init__(lock, ip, interval, name, timeout)


def receiver_loop(sock, status):
  while True:
    data, addr = sock.recvfrom(65535)

    ip, port, _, _ = addr
    try:
      op, pid, payload = ThreadingSmokeProtocol.decode_packet(data)
    except Exception as e:
      warnings.warn(f"Decoding exception: {e}")
      continue

    if op == SmokeProtocol.PKT_TYPE_PING:
      sock.sendto(SmokeProtocol.gen_pong(pid, payload), (ip, port))
    elif op == SmokeProtocol.PKT_TYPE_PONG:
      if ip in status:
        status[ip].process_pong(pid)
      else:
        warnings.warn(f"Packet from unknown IP {ip}")
    else:
      warnings.warn(f"Malformed packet from IP {ip}")
    

def initiator_loop(sock, status, port, interval):
  while True:
    for ip in status:
      sock.sendto(status[ip].emit_ping(),(ip, port))
    time.sleep(interval)



def ui_loop(status, screen_refresh):
  try:
    stdscr = curses.initscr()
    stdscr.nodelay(True)

    last = {}
    while True:
      k = stdscr.getch()
      if k > 0 and chr(k) == 'q':
        sys.exit()

      for ln, ip in enumerate(sorted(status.keys(), reverse=True)):
        sent, received, lost, outoforder, rtt_avg, rtt_var = status[ip].get_human_metrics()

        last_sent, last_received, last_lost, last_outoforder = last.get(ip, (0,0,0,0))
        oorate, lostrate = ((outoforder-last_outoforder)/screen_refresh, (lost-last_lost)/screen_refresh, )  
        last[ip] = (sent, received, lost, outoforder)

        if status[ip].name:
          l = f'{status[ip].name} tx:{sent} rx:{received} outordr:{outoforder} ({oorate}/s) lost:{lost} ({lostrate}/s) rtt_avg:{round(rtt_avg, 3)} ms rtt_sd:{round(math.sqrt(rtt_var),3)}'
        else:
          l = f'{ip} tx:{sent} rx:{received} outordr:{outoforder} ({oorate}/s) lost:{lost} ({lostrate}/s) rtt_avg:{round(rtt_avg, 3)} ms rtt_sd:{round(math.sqrt(rtt_var),3)}'

        args = []
        if oorate > 0 or lostrate >0:
          args.append(curses.A_STANDOUT)

        stdscr.addstr(ln, 0, l, *args)
        stdscr.clrtoeol()

      stdscr.refresh()
      time.sleep(screen_refresh)

  finally:
    curses.endwin()

def prometheus_server_loop(status, listen=PROMETHEUS_SERVER_LISTEN, port=PROMETHEUS_SERVER_PORT):
  namespace = "udpsmoke"

  class PrometheusHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
      self.send_response(http.HTTPStatus.OK)
      self.end_headers()
      for ip in status:
        for m in status[ip].get_prometheus_metrics():
          self.wfile.write(m.render(namespace))

    def log_request(self, code='-', size='-'):
      if isinstance(code, http.HTTPStatus):
        code = code.value
      logging.info('"%s" %s %s', self.requestline, str(code), str(size))


  class TCP6Server(socketserver.TCPServer):
    def server_bind(self):
        """Called by constructor to bind the socket.
        May be overridden.
        """
        if self.allow_reuse_address:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        self.socket.bind(self.server_address)
        self.server_address = self.socket.getsockname()

    allow_reuse_address = True
    address_family = socket.AF_INET6

  httpd = TCP6Server((listen, port), PrometheusHandler)
  httpd.serve_forever()
  

def main():
  parser = argparse.ArgumentParser(description='run UDP ping with a list of remote servers and run UDP echo server')
  parser.add_argument('-v', '--verbose', dest='verb', action='store_const', const=True, default=False, help='verbose output')
  parser.add_argument('-t', '--targets', dest='tgts', help="list of targets")
  parser.add_argument('-p', '--port', dest='port', help="port to use", default=54321)
  parser.add_argument('-i', '--interval', dest='interval', help="time interval between pings (s)", default=0.2)
  parser.add_argument('-r', '--refresh', dest='refresh', help="curses UI refresh interval (s)", default=1)
  parser.add_argument('-b', '--bind', dest='bind', help="bind IPv6-formatted (IPv6 or ::ffff:<IPv4>) address", default='::')

  args = parser.parse_args()

  if args.verb:
    logging.basicConfig(level=logging.DEBUG)
  else:
    logging.basicConfig(level=logging.INFO)

  def normalize_ip(hostname):
    try:
      if ipaddress.ip_address(hostname).version == 4:
        return f'::ffff:{hostname}'
      else:
        return hostname
    except ValueError:
      pass

    try:
      return socket.getaddrinfo(hostname, None, socket.AF_INET6, socket.SOCK_DGRAM)[0][4][0]
    except socket.gaierror:
      pass

    try:
      return socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]
    except socket.gaierror:
      pass

    raise ValueError(f"Hostname {hostname} it not an IP address nor can it be resolved to IP address.")


  def get_tgt(l):
    spl = l.strip().split(' ')
    if len(spl) == 1:
      return (normalize_ip(spl[0].strip()), None)
    else:
      return (normalize_ip(spl[0].strip()), spl[1].strip())

  if args.tgts:
    with open(args.tgts, 'r') as fd:
      tgtips = [get_tgt(l) for l in fd.readlines() if l.strip()]
  else:
    tgtips = []

  port = int(args.port)
  interval = float(args.interval)
  refresh = int(args.refresh)

  status = {ip:ThreadingSmokeProtocol(ip, interval, name) for ip, name in tgtips}

  sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
  sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
  sock.bind((args.bind, port))

  threads = []

  threads.append(threading.Thread(target=receiver_loop, args=(sock, status)))
  threads[-1].setDaemon(True)
  threads[-1].start()

  threads.append(threading.Thread(target=initiator_loop, args=(sock, status, port, interval)))
  threads[-1].setDaemon(True)
  threads[-1].start()

  threads.append(threading.Thread(target=prometheus_server_loop, args=(status,)))
  threads[-1].setDaemon(True)
  threads[-1].start()

  if refresh:
    ui_loop(status, refresh)
  else:
    while True:
      time.sleep(1)


if __name__ == '__main__':
  main()

