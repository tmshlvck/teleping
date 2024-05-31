# coding: utf-8
"""
UDPPing
Based on The UDP Smoke - fast UDP ping that gathers statistics

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
from typing import List, Dict, Tuple, Optional
import struct
from threading import Thread, Lock, Event
import queue
from ipaddress import IPv4Address, IPv6Address, ip_address
import socket
import time
import os
import math
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily
from prometheus_client.registry import Collector
from collections import deque



class RunningAvg:
    _qsize: int
    _queue: deque[float]
    mean: float
    variance: float

    __slots__ = tuple(__annotations__)

    def __init__(self, window_sec: float = 15, update_interval_sec: float = 1):
        self._qsize = math.ceil(float(window_sec)/update_interval_sec)
        self._queue = deque([0.0] * self._qsize, maxlen=self._qsize)
        self.mean = 0.0
        self.variance = 0.0

    def update(self, value: float):
        prev_mean = self.mean
        oldest_value = self._queue[0]
        self.mean = prev_mean + (value - oldest_value) / self._qsize
        self._queue.append(value)
        self.variance += (value - oldest_value) * ((value - self.mean) + (oldest_value - prev_mean)) / (self._qsize - 1)

    @property
    def sdev(self):
        return math.sqrt(self.variance)


class RunningFract:
    _evqueue: deque[float]
    _subqueue: deque[float]

    __slots__ = tuple(__annotations__)

    def __init__(self, window_sec: float = 15, update_interval_sec: float = 1):
        qsize = math.ceil(float(window_sec)/update_interval_sec)
        self._evqueue = deque([0.0] * qsize, maxlen=qsize)
        self._subqueue = deque([0.0] * qsize, maxlen=qsize+1)

    def event(self, value: float = 1):
        self._evqueue.append(value)
        self._subqueue.append(0)

    def subevent(self, value: float = 1):
        self._subqueue[-1] = value

    @property
    def mean(self):
        #print(f'{self._evqueue=} {self._subqueue=}')
        seq = sum(self._evqueue)
        ssq = sum(self._subqueue)

        if seq == 0:
            return 0
        elif float(ssq) / seq > 1:
            return 1.0
        else:
            return float(ssq) / seq




class HostContext:
    EXPIRY_THRESHOLD_SEC = 60
    PING_TIMEOUT_SEC = 5

    _host: str
    _ip: str
    _afi: int
    _active: bool
    _stats_interval_sec: float
    _pending: Dict[int,float]
    _rtt: List[RunningAvg]
    _loss_rate: List[RunningFract]

    last_rx_time: float
    total_tx_ping: int
    total_rx_ping_ok: int
    total_rx_ping_corrupt: int
    total_rx_pong_ok: int
    total_rx_pong_corrupt: int
    total_rx_malformed: int
    total_lost: int

    __slots__ = tuple(__annotations__)

    INTERVALS = [15, 60, 300]
    METRICS = [a for a in __annotations__ if not a.startswith('_')] + [f'rtt_avg_{i}s' for i in INTERVALS] + [f'loss_rate_{i}s' for i in INTERVALS]

    def __init__(self, ip: str, afi: int, active: bool = False, update_interval_sec: float = 1, host: str = None):
        if host == None:
            self._host = ip
        else:
            self._host = host
        self._ip = ip
        self._afi = afi
        self._active = active
        self._pending = {}
        self._rtt = [RunningAvg(i, update_interval_sec) for i in self.INTERVALS]
        self._loss_rate = [RunningFract(i, update_interval_sec) for i in self.INTERVALS]

        for m in [a for a in self.__annotations__ if not a.startswith('_')]:
            setattr(self, m, 0)

    @property
    def rtt_avg_15s(self):
        return self._rtt[0].mean
    
    @property
    def rtt_avg_60s(self):
        return self._rtt[1].mean
    
    @property
    def rtt_avg_300s(self):
        return self._rtt[2].mean
    
    @property
    def loss_rate_15s(self):
        return self._loss_rate[0].mean
    
    @property
    def loss_rate_60s(self):
        return self._loss_rate[1].mean
    
    @property
    def loss_rate_300s(self):
        return self._loss_rate[2].mean
    
    def get_host(self):
        return self._host

    def get_metrics(self, extended: bool = False) -> Dict[str, int|float]:
        if extended:
            return {m: getattr(self, m) for m in self.METRICS} | {'host': self._host, 'ip': self._ip, 'afi': self._afi, 'active': self._active}
        else:
            return {m: getattr(self, m) for m in self.METRICS}

    def is_expired(self) -> bool:
        return (not self._active and (time.time() - self.last_rx_time) > self.EXPIRY_THRESHOLD_SEC) 

    def ping_tx(self, txtime: float, pktid: int, txlen: int):
        self.total_tx_ping += 1
        self._pending[pktid] = txtime
        for l in self._loss_rate:
            l.event()

    def failed_tx(sefl, txtime: float, pktid: int):
        pass

    def ping_rx(self, rtime: float, payload_ok: bool):
        self.last_rx_time = rtime
        if payload_ok:
            self.total_rx_ping_ok += 1
        else:
            self.total_rx_ping_corrupt += 1

    def pong_rx(self, rtime: float, pktid: int, payload_ok: bool):
        self.last_rx_time = rtime
        if pktid in self._pending:
            rtt = rtime*1000 - self._pending[pktid]*1000
            for r in self._rtt:
                r.update(rtt)
            self._pending.pop(pktid)
        else:
            self.total_rx_pong_corrupt += 1
            return

        if payload_ok:
            self.total_rx_pong_ok += 1
        else:
            self.total_rx_pong_corrupt += 1

    def malformed_rx(self, rtime: float, exc: Exception):
        self.last_rx_time = rtime
        self.total_rx_malformed += 1

    def periodic_update(self):
        t = time.time()
        to_delete = []
        for p in self._pending:
            if t - self._pending[p] > self.PING_TIMEOUT_SEC:
                to_delete.append(p)
        for p in to_delete:
            self._pending.pop(p)
            self.total_lost += 1
            for l in self._loss_rate:
                l.subevent()


class UDPPing(Collector):
    stats: Dict[str, HostContext]
    stats_lock: Lock
    stop_flag: Event
    rx_thread4: Optional[Thread]
    rx_thread6: Optional[Thread]
    rx_processor_thread: Thread
    tx_thread: Thread
    p_thread: Thread
    rxq: queue.Queue
    port: int
    tx_interval_sec: float
    sock4: Optional[socket.socket]
    sock6: Optional[socket.socket]
    last_pktid: int = 0
    txlen: int = 100

    HEADER = struct.Struct('!cxxxQII') # [type: byte, pad, pad, pad, pktid: ulonglong, len: uint, csum: uint]
    MAX_PKTID = (2**64)-1
    PKT_TYPE_PING = b'P'
    PKT_TYPE_PONG = b'R'
    PKT_TYPE_PONG_CORRUPTED_DATA = b'C'

    @staticmethod
    def csum(data: bytes) -> int:
        s = 0
        for b in bytes(data):
            s = (s + b) & 0xFFFFFFFF
        return s

    @classmethod
    def gen_ping(cls, pktid: int, data_len: int, randomized: bool =False) -> bytes:
        if randomized:
            x = os.urandom(1)
            data = bytes([ord(x)+i for i in range(data_len)])
        else:
            data = ('*' * data_len).encode('ascii')
        
        return cls.HEADER.pack(cls.PKT_TYPE_PING, pktid, len(data), cls.csum(data)) + data

    @classmethod
    def decode_packet(cls, data: bytes) -> Tuple[str, int, int, int, bytes]: # op, pktid, len, rcsum, data
        op, pktid, plen, rcsum = cls.HEADER.unpack_from(data)
        data = data[cls.HEADER.size:]
        return op, pktid, plen, rcsum, data

    @classmethod
    def verify_packet(cls, data: bytes, plen: int, rcsum: int):
        if len(data) == plen and cls.csum(data) == rcsum:
            return True
        else:
            return False

    @classmethod
    def gen_pong(cls, pid, data, recv_ok=False):
        return cls.HEADER.pack(cls.PKT_TYPE_PONG if recv_ok else cls.PKT_TYPE_PONG_CORRUPTED_DATA, pid, len(data), cls.csum(data)) + data
    
    def __init__(self):
        self.stats = {}
        self.stats_lock = Lock()
        self.stop_flag = Event()
        self.rxq = queue.Queue()
    
    def _expire_targets_unsafe(self):
        to_cleanup = []
        for tk in self.stats:
            if self.stats[tk].is_expired():
                to_cleanup.append(tk)
        for tk in to_cleanup:
            self.stats.pop(tk)

    def set_targets(self, tgts: Dict[IPv4Address|IPv6Address|str, str]):
        normtgts = {ip_address(tk) : v for tk, v in tgts.items()}
        with self.stats_lock:
            for t,h in normtgts.items():
                if str(t) in self.stats:
                    self.stats[str(t)]._active = True
                else:
                    self.stats[str(t)] = HostContext(str(t), t.version, active=True, update_interval_sec=self.tx_interval_sec, host=h)

            for tk in self.stats:
                if not ip_address(tk) in tgts:
                    self.stats[tk]._active = False

            self._expire_targets_unsafe()

    def _rx(self, sock: socket.socket, afi: int):
        try:
            logging.debug("_receiver_loop up")
            while not self.stop_flag.is_set():
                try:
                    data, addr = sock.recvfrom(65535)
                except TimeoutError:
                    continue
            
                rtime = time.time()

                sip, sport = addr[0:2] # addr from IPv6 recvfrom can contain extra parameters
                try:
                    op, pktid, plen, rcsum, payload = self.decode_packet(data)
                    payload_ok = self.verify_packet(payload, plen, rcsum)
                except struct.error as e:
                    self.rxq.put((afi, rtime, sip, sport, None, None, False, e))
                    continue

                if op == self.PKT_TYPE_PING:
                    sock.sendto(self.gen_pong(pktid, payload, payload_ok), (sip, sport))

                self.rxq.put((afi, rtime, sip, sport, op, pktid, payload_ok, None))
        except:
            logging.exception("_receiver_loop exception:")
            raise

    def _rx_processor(self):
        while not self.stop_flag.is_set():
            try:
                afi, rtime, sip, sport, op, pktid, payload_ok, exc = self.rxq.get(timeout=1)
            except queue.Empty:
                continue

            with self.stats_lock:
                if not sip in self.stats:
                    self.stats[sip] = HostContext(sip, afi)

                if op == self.PKT_TYPE_PING:
                    self.stats[sip].ping_rx(rtime, payload_ok)
                elif op == self.PKT_TYPE_PONG:
                    self.stats[sip].pong_rx(rtime, pktid, payload_ok)
                elif op == None:
                    self.stats[sip].malformed_rx(rtime, exc)

    def _gen_pktid_unsafe(self):
        self.last_pktid += 1
        if self.last_pktid >= self.MAX_PKTID:
            self.last_pktid = 0
        return self.last_pktid

    def _tx(self):
        logging.debug("_initiator_loop up")
        while not self.stop_flag.is_set():
            try:
                with self.stats_lock:
                    for dip in self.stats:
                        t = self.stats[dip]
                        pktid = self._gen_pktid_unsafe()
                        txtime = time.time()

                        try:
                            if t._afi == 4 and self.sock4:
                                self.sock4.sendto(self.gen_ping(pktid, self.txlen, False),(dip, self.port))
                            elif t._afi == 6 and self.sock6:
                                self.sock6.sendto(self.gen_ping(pktid, self.txlen, False),(dip, self.port))
                            else:
                                t.failed_tx(txtime, pktid)
                        except OSError:
                            logging.exception("_initiator_loop send exception:")
                            t.failed_tx(txtime, pktid)

                        self.stats[dip].ping_tx(txtime, pktid, self.txlen)

                time.sleep(self.tx_interval_sec)
            except:
                logging.exception("_initiator_loop exception:")
                raise

    def _periodic(self):
        while not self.stop_flag.is_set():
            try:
                with self.stats_lock:
                    self._expire_targets_unsafe()

                    for t in self.stats:
                        self.stats[t].periodic_update()
            except Exception as e:
                logging.exception("_periodic")
                raise

            time.sleep(self.tx_interval_sec)

    
    def start(self, bind_address4: Optional[str], bind_address6: Optional[str], port: int, tx_interval_sec: float = 1):
        self.port = port
        self.tx_interval_sec = tx_interval_sec

        if bind_address4:
            self.sock4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock4.settimeout(1)
            self.sock4.bind((bind_address4, port))

            self.rx_thread4 = Thread(target=lambda: self._rx(self.sock4, 4), name='udpping_rx')#, daemon=True)
            self.rx_thread4.start()
            logging.info(f"Initialized IPv4 socket on address {bind_address4}")
        else:
            logging.info(f"Skipped IPv4 socket init")
            self.sock4 = None
            self.rx_thread4 = None

        if bind_address6:
            self.sock6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            self.sock6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            self.sock6.settimeout(1)
            self.sock6.bind((bind_address6, port))
            logging.info(f"Initialized IPv6 socket on address {bind_address6}")

            self.rx_thread6 = Thread(target=lambda: self._rx(self.sock6, 6), name='udpping_rx')#, daemon=True)
            self.rx_thread6.start()
        else:
            logging.info(f"Skipped IPv6 socket init")
            self.sock6 = None
            self.rx_thread6 = None

        self.rx_processor_thread = Thread(target=self._rx_processor, name='udpping_update')#, daemon=True)
        self.rx_processor_thread.start()

        self.tx_thread = Thread(target=self._tx, name='udpping_update')#, daemon=True)
        self.tx_thread.start()

        self.p_thread = Thread(target=self._periodic, name='udpping_periodic')#, daemon=True)
        self.p_thread.start()
    
    def stop(self):
        logging.info("Initiating UDPPing stop")
        self.stop_flag.set()

        try:
            self.tx_thread.join()
        except:
            pass

        if self.sock4:
            self.sock4.close()
        if self.sock6:
            self.sock6.close()

        try:
            if self.rx_thread4:
                self.rx_thread4.join()
        except:
            pass
        try:
            if self.rx_thread6:
                self.rx_thread6.join()
        except:
            pass
        try:
            self.rx_processor_thread.join()
        except:
            pass
        try:
            self.p_thread.join()
        except:
            pass

    def collect(self):
        output = {}
        for k in HostContext.METRICS:
            if 'total' in k:
                output[k] = CounterMetricFamily(k, f'Counter {k}', labels=['tgtip', 'tgtname'])
            else:
                output[k] = GaugeMetricFamily(k, f'Gauge {k}', labels=['tgtip', 'tgtname'])
        
        with self.stats_lock:
            for tip,hc in self.stats.items():
                md = hc.get_metrics()
                for k in md:
                    output[k].add_metric([tip, hc.get_host()], md[k] if md[k] != None else 0)

        for k in output:
            yield output[k]

    def get_hostmetrics(self, extended: bool = False) -> Dict[str, Dict[str, int|float|str]]:
        with self.stats_lock:
            return {h: self.stats[h].get_metrics(extended) for h in self.stats}
        
    
def test():
    try:
        import ipaddress
        up = UDPPing()
        up.set_targets([ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("::1")])
        up.start('0.0.0.0', '::', 54321)
        while True:
            res = up.get_stats()
            for t in res:
                print(f"{t:<30} {res[t]}")
            time.sleep(5)
    except KeyboardInterrupt:
        up.stop()
        raise


if __name__ == '__main__':
    test()