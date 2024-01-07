#!/usr/bin/env python3
# coding: utf-8

"""
The UDP Smoke - fast UDP ping that gathers statistics

Copyright (C) 2021 Tomas Hlavacek (tmshlvck@gmail.com)

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
PROMETHEUS_SERVER_LISTEN=None
PROMETHEUS_SERVER_PORT=8888


import click
import logging
import asyncio
import time
import csv
import struct
import warnings
import ipaddress
import socket
import curses
import math
import sys
import aiohttp

# UDP Async Server Boilerplate

class DatagramEndpointProtocol(asyncio.DatagramProtocol):
  """Datagram protocol for the endpoint high-level interface."""

  def __init__(self, endpoint):
    self._endpoint = endpoint

  # Protocol methods

  def connection_made(self, transport):
    self._endpoint._transport = transport

  def connection_lost(self, exc):
    assert exc is None
    if self._endpoint._write_ready_future is not None:
      self._endpoint._write_ready_future.set_result(None)
    self._endpoint.close()

  # Datagram protocol methods

  def datagram_received(self, data, addr):
    self._endpoint.feed_datagram(data, addr)

  def error_received(self, exc):
    msg = 'Endpoint received an error: {!r}'
    warnings.warn(msg.format(exc))

  # Workflow control

  def pause_writing(self):
    assert self._endpoint._write_ready_future is None
    loop = self._endpoint._transport._loop
    self._endpoint._write_ready_future = loop.create_future()

  def resume_writing(self):
    assert self._endpoint._write_ready_future is not None
    self._endpoint._write_ready_future.set_result(None)
    self._endpoint._write_ready_future = None


# Enpoint classes

class Endpoint:
  """High-level interface for UDP enpoints.
  Can either be local or remote.
  It is initialized with an optional queue size for the incoming datagrams.
  """

  def __init__(self, queue_size=None):
    if queue_size is None:
        queue_size = 0
    self._queue = asyncio.Queue(queue_size)
    self._closed = False
    self._transport = None
    self._write_ready_future = None

  # Protocol callbacks

  def feed_datagram(self, data, addr):
    try:
      self._queue.put_nowait((data, addr))
    except asyncio.QueueFull:
      warnings.warn('Endpoint queue is full')

  def close(self):
    # Manage flag
    if self._closed:
      return
    self._closed = True
    # Wake up
    if self._queue.empty():
      self.feed_datagram(None, None)
    # Close transport
    if self._transport:
      self._transport.close()

  # User methods

  def sendto(self, data, addr):
    """Send a datagram to the given address."""
    if self._closed:
      raise IOError("Enpoint is closed")
    self._transport.sendto(data, addr)

  async def recvfrom(self):
    """Wait for an incoming datagram and return it with
    the corresponding address.
    This method is a coroutine.
    """
    if self._queue.empty() and self._closed:
      raise IOError("Enpoint is closed")
    data, addr = await self._queue.get()
    if data is None:
      raise IOError("Enpoint is closed")
    return data, addr

  def abort(self):
    """Close the transport immediately."""
    if self._closed:
      raise IOError("Enpoint is closed")
    self._transport.abort()
    self.close()

  async def drain(self):
    """Drain the transport buffer below the low-water mark."""
    if self._write_ready_future is not None:
      await self._write_ready_future

  # Properties

  @property
  def address(self):
    """The endpoint address as a (host, port) tuple."""
    return self._transport.get_extra_info("socket").getsockname()

  @property
  def closed(self):
    """Indicates whether the endpoint is closed or not."""
    return self._closed


# High-level coroutines

async def open_datagram_endpoint(host, port, *, endpoint_factory=Endpoint, **kwargs):
  """Open and return a datagram endpoint.
  The default endpoint factory is the Endpoint class.
  The endpoint can be made local or remote using the remote argument.
  Extra keyword arguments are forwarded to `loop.create_datagram_endpoint`.
  """
  loop = asyncio.get_event_loop()
  endpoint = endpoint_factory()
  kwargs['local_addr'] = host, port
  kwargs['protocol_factory'] = lambda: DatagramEndpointProtocol(endpoint)
  await loop.create_datagram_endpoint(**kwargs)
  return endpoint


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


class AsyncSmokeProtocol(SmokeProtocol):
  class NoLock:
    def acquire(self):
      pass
    def release(self):
      pass

  def __init__(self, ip, interval, name=None, timeout=TIMEOUT):
    lock = self.NoLock()
    super().__init__(lock, ip, interval, name, timeout)


async def receiver_task(ep, status):
  while True:
    data, addr = await ep.recvfrom()

    ip, port, _, _ = addr
    try:
      op, pid, payload = AsyncSmokeProtocol.decode_packet(data)
    except Exception as e:
      warnings.warn(f"Decoding exception: {e}")
      continue

    if op == SmokeProtocol.PKT_TYPE_PING:
      ep.sendto(SmokeProtocol.gen_pong(pid, payload), (ip, port))
    elif op == SmokeProtocol.PKT_TYPE_PONG:
      if ip in status:
        status[ip].process_pong(pid)
      else:
        warnings.warn(f"Packet from unknown IP {ip}")
    else:
      warnings.warn(f"Malformed packet from IP {ip}")


async def initiator_task(ep, status, port, interval):
  while True:
    for ip in status:
      ep.sendto(status[ip].emit_ping(),(ip, port))
    await asyncio.sleep(interval)


async def ui_task(status, screen_refresh):
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
      await asyncio.sleep(screen_refresh)

  finally:
    curses.endwin()


async def csv_task(status, filename, interval):
  csv_refresh = interval*25
  if csv_refresh < 1:
    csv_refresh = 1
  if csv_refresh > 30:
    csv_refresh = interval

  while True:
    with open(filename, "a") as csv_file:
      wr = csv.writer(csv_file, quoting=csv.QUOTE_MINIMAL)
      for ip in status:
        sent, received, lost, outoforder, rtt_avg, rtt_var = status[ip].get_human_metrics()
        wr.writerow([ip, sent, received, lost, outoforder, rtt_avg, rtt_var])

    await asyncio.sleep(csv_refresh)


import aiohttp.web
async def prometheus_task(status, listen=PROMETHEUS_SERVER_LISTEN, port=PROMETHEUS_SERVER_PORT):
  namespace = "udpsmoke"
  async def handler(request):
    b = b''
    for ip in status:
      for m in status[ip].get_prometheus_metrics():
        b += m.render(namespace)
    return aiohttp.web.Response(body=b)

  app = aiohttp.web.Application()
  app.add_routes([aiohttp.web.get('/', handler)])

  logging.getLogger('aiohttp.access').setLevel(logging.WARNING)
  logging.getLogger('aiohttp.client').setLevel(logging.WARNING)
  logging.getLogger('aiohttp.internal').setLevel(logging.WARNING)
  logging.getLogger('aiohttp.server').setLevel(logging.WARNING)
  logging.getLogger('aiohttp.web').setLevel(logging.WARNING)
  logging.getLogger('aiohttp.websocket').setLevel(logging.WARNING)
  await aiohttp.web._run_app(app, host=listen, port=port, print=None)


async def start_all(tgtips, port, interval, refresh, csvfile, bind):
  ep = await open_datagram_endpoint(bind, port)

  tsk = []
  status = {ip:AsyncSmokeProtocol(ip, interval, name) for ip, name in tgtips}
  tsk.append(asyncio.create_task(receiver_task(ep, status)))

  tsk.append(asyncio.create_task(initiator_task(ep, status, port, interval)))

  tsk.append(asyncio.create_task(ui_task(status, refresh)))

  tsk.append(asyncio.create_task(prometheus_task(status)))

  if csvfile:
    tsk.append(asyncio.create_task(csv_task(status, csvfile, interval)))

  await asyncio.gather(*tsk)


@click.command(help="run UDP ping with a list of remote servers and run UDP echo server")
@click.option('-v', '--verbose', 'verb', help="verbose output", is_flag=True)
@click.option('-t', '--targets', 'tgts', help="list of targets", type=click.File('r'), required=True)
@click.option('-p', '--port', 'port', help="port to use", default=54321)
@click.option('-i', '--interval', 'interval', help="time interval between pings", default=0.2)
@click.option('-r', '--refresh', 'refresh', help="curses UI refresh interval (s)", default=1)
@click.option('-c', '--csv', 'csvfile', help="CSV output", type=click.Path())
@click.option('-b', '--bind', 'bind', help="bind IPv6-formatted (IPv6 or ::ffff:<IPv4>) address", default='::')
def main(verb, tgts, port, interval, refresh, csvfile, bind):
  if verb:
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


  tgtips = [get_tgt(l) for l in tgts.readlines() if l.strip()]
  port = int(port)

  asyncio.run(start_all(tgtips, port, interval, refresh, csvfile, bind))


if __name__ == '__main__':
    main()

