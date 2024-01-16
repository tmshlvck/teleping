# coding: utf-8
"""
UDPPing
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


import logging
import time
import datetime
import struct
import ipaddress
import socket
import threading
import queue
import os
import copy
from typing import List, Dict, Tuple

from telephant.prometheus import Counter,Summary

def last_tsv(d: List[Tuple[float, int|float]], divide: float=1):
    if len(d) > 0:
        if isinstance(d[-1][1], float) or divide != 1:
            return f"{(d[-1][1]/divide):.1f}"
        else:
            return str(d[-1][1])
    else:
        return "N/A"


def percent(a: int|float, b:int|float):
    if b == 0:
        logging.error(f"Can not compute percentage {a} / {b}")
        return 0

    p = 100*a/b
    # fix possible rounding errors
    if p > 100:
        return 100.0
    elif p < 0:
        return 0.0
    else:
        return p

def humanize_ip(ip):
    ipm = ipaddress.ip_address(ip).ipv4_mapped
    if ipm:
        return str(ipm)
    else:
        return str(ip)

def report_ts(sum):
    return [{'timestamp':t, 'time_local': datetime.datetime.fromtimestamp(t).astimezone(), 'value': v} for t,v in sum]

class CounterUnsafe:
    dpts: List[int] # [datapoint,]
    sum_15s: List[Tuple[float,float]] # [(timestamp, datapoint),]
    sum_5m: List[Tuple[float,float]] # [(timestamp, datapoint),]
    total: int
    keep_15s: int
    keep_5m: int

    def __init__(self, keep_15s=240, keep_5m=8640):
        self.dpts = []
        self.sum_15s = []
        self.sum_5m = []
        self.total = 0
        self.keep_15s = keep_15s
        self.keep_5m = keep_5m

    def record(self, value: int = 1):
        self.dpts.append(value)
        self.total += value

    def aggregate(self, time: float):
        self.sum_15s.append((time, sum(self.dpts)))
        self.dpts = []

        if len(self.sum_15s) >= 20 and self.sum_15s[-20][0] > (self.sum_5m[-1][0] if len(self.sum_5m) > 0 else 0):
            self.sum_5m.append((time, sum([v for _,v in self.sum_15s[-20:]])))

        if len(self.sum_15s) > self.keep_15s:
            self.sum_15s = self.sum_15s[len(self.sum_15s)-self.keep_15s:]

        if len(self.sum_5m) > self.keep_5m:
            self.sum_5m = self.sum_5m[len(self.sum_5m)-self.keep_5m:]

    def is_inactive(self):
        for _,v in self.dpts:
            if v > 0:
                return False
            
        for _,v in self.sum_15s:
            if v > 0:
                return False

        if len(self.sum_5m) > 24: # 2 hours
            for _,v in self.sum_5m[-24:]:
                if v > 0:
                    return False
        
        return True

    def get_prometheus_data(self, name: str, tags: Dict[str, str]):
        return Counter(name, self.total, tags)
    
    def get_report_data(self, name: str, relate_to:'CounterUnsafe' = None):
        """
        Warning: This method returns encapsulated references to the objects, deep copy under lock protection is needed to avoid races
        """
        return {name: {'total': self.total, 'last_datapoints': self.dpts, 'sum_15sec': report_ts(self.sum_15s), 'sum_5min': report_ts(self.sum_5m)}}
    
    def get_printable(self, relate_to:'CounterUnsafe' = None):
        return f'{self.total} {last_tsv(self.sum_15s, 15)}/s'

class PercentCounterUnsafe(CounterUnsafe):
    percent_15s: List[Tuple[float,float]] # [(timestamp, datapoint),]
    percent_5m: List[Tuple[float,float]] # [(timestamp, datapoint),]
    total_percent: float

    def __init__(self, keep_15s=240, keep_5m=8640):
        super().__init__(keep_15s, keep_5m)
        self.percent_15s = []
        self.percent_5m = []
        self.total_percent = 0

    def record(self, value: int = 1, relate_to: CounterUnsafe = None):
        """
        The relate_to counter has to be already aggregated for exactly the same time when this method is called !!!
        """
        self.dpts.append(value)
        self.total += value
        self.total_percent = percent(self.total, relate_to.total)

    def aggregate(self, time: float, relate_to: CounterUnsafe = None):
        """
        The relate_to counter has to be already aggregated for exactly the same time when this method is called !!!
        """
        super().aggregate(time)

        if len(self.sum_15s) > 0 and len(relate_to.sum_15s) > 0 and self.sum_15s[-1][0] == time and relate_to.sum_15s[-1][0] == time:
            self.percent_15s.append((time, percent(self.sum_15s[-1][1], relate_to.sum_15s[-1][1])))

        if len(self.sum_5m) > 0 and len(relate_to.sum_5m) > 0 and self.sum_5m[-1][0] == time and relate_to.sum_5m[-1][0] == time:
            self.percent_5m.append((time, percent(self.sum_5m[-1][1], relate_to.sum_5m[-1][1])))

        if len(self.percent_15s) > self.keep_15s:
            self.percent_15s = self.percent_15s[len(self.percent_15s)-self.keep_15s:]

        if len(self.percent_5m) > self.keep_5m:
            self.percent_5m = self.percent_5m[len(self.percent_5m)-self.keep_5m:]

    def get_report_data(self, name: str):
        """
        Warning: This method returns encapsulated references to the objects, deep copy under lock protection is needed to avoid races
        """
        return {name: {'total': self.total, 'total_percent': self.total_percent, 'last_datapoints': self.dpts, 'sum_15sec': report_ts(self.sum_15s),
                       'percent_15sec': report_ts(self.percent_15s), 'sum_5min': report_ts(self.sum_5m), 'percent_5min': report_ts(self.percent_5m)}}
    
    def get_printable(self):
        #return f'{last_tsv(self.sum_15s)} ({last_tsv(self.percent_15s)}%) {last_tsv(self.sum_5m)} ({last_tsv(self.percent_5m)}) {self.total} ({self.total_percent:.1f})'
        return f'{self.total} ({self.total_percent:.1f} %) {last_tsv(self.sum_15s,15)}/s'

class AvgSummaryUnsafe:
    dpts: List[float|int] # [datapoint,]
    dpts_roll: List[float|int] # [datapoint,]
    avg_15s: List[Tuple[float,float]] # [(timestamp, datapoint),]
    avg_5m: List[Tuple[float,float]] # [(timestamp, datapoint),]
    avg_roll: float
    keep_15s: int
    keep_5m: int
    dpts_count: int
    dpts_sum: float|int

    def __init__(self, keep_15s=240, keep_5m=8640, avg_roll_count=20):
        self.dpts = []
        self.dpts_roll = []
        self.avg_15s = []
        self.avg_5m = []
        self.avg_roll = 0
        self.keep_15s = keep_15s
        self.keep_5m = keep_5m
        self.avg_roll_count = avg_roll_count
        self.dpts_count = 0
        self.dpts_sum = 0

    def record(self, value: float|int):
        self.dpts.append(value)
        self.dpts_count += 1
        self.dpts_sum += value
        self.dpts_roll.append(value)
        if len(self.dpts_roll) > self.avg_roll_count:
            self.avg_roll += (value - self.dpts_roll.pop(0))/self.avg_roll_count
        else:
            self.avg_roll += value/self.avg_roll_count

    def aggregate(self, time: float):
        if len(self.dpts) == 0:
            return

        self.avg_15s.append((time, sum(self.dpts)/len(self.dpts)))
        self.dpts = []

        if len(self.avg_15s) >= 20 and self.avg_15s[-20][0] > (self.avg_5m[-1][0] if len(self.avg_5m) > 0 else 0):
            self.avg_5m.append((time, sum([v for _,v in self.avg_15s[-20:]])/20))

        if len(self.avg_15s) > self.keep_15s:
            self.avg_15s = self.avg_15s[len(self.avg_15s)-self.keep_15s:]

        if len(self.avg_5m) > self.keep_5m:
            self.avg_5m = self.avg_5m[len(self.avg_5m)-self.keep_5m:]

    def get_prometheus_data(self, name: str, tags: Dict[str, str]):
        return Summary(name, self.dpts_sum, self.dpts_count, tags)
    
    def get_report_data(self, name: str):
        """
        Warning: This method returns encapsulated references to the objects, deep copy under lock protection is needed to avoid races
        """
        return {name: {'last_rolling_avg': self.avg_roll, 'last_rolling_avg_datapoints': self.avg_roll_count, 'last_datapoints': self.dpts, 'avg_15sec': report_ts(self.avg_15s), 'avg_5min': report_ts(self.avg_5m)}}
    
    def get_printable(self):
        return f'{self.avg_roll:.1f} {last_tsv(self.avg_15s)} {last_tsv(self.avg_5m)}'


class UDPPingHostData:
    KEEP_15s = 240 # 60 min
    KEEP_5m = 8640 # 30 days

    ip: str
    name: str
    proto: int

    last_rx_pktid: int

    ts_ping_sent: CounterUnsafe
    ts_ping_recv: CounterUnsafe
    ts_pong_recv: PercentCounterUnsafe
    ts_corrupt_recv: PercentCounterUnsafe
    ts_lost: PercentCounterUnsafe
    ts_rtt: AvgSummaryUnsafe
    ts_outoforder_recv: PercentCounterUnsafe

    __slots__ = tuple(__annotations__)  
    
    def __init__(self, ip, name):
        self.ip = ip
        self.name = name
        self.proto = 4 if ipaddress.ip_address(ip).ipv4_mapped else 6

        self.last_rx_pktid = 0
        self.ts_ping_sent = CounterUnsafe(self.KEEP_15s, self.KEEP_5m)
        self.ts_ping_recv = CounterUnsafe(self.KEEP_15s, self.KEEP_5m)
        self.ts_pong_recv = PercentCounterUnsafe(self.KEEP_15s, self.KEEP_5m)
        self.ts_corrupt_recv = PercentCounterUnsafe(self.KEEP_15s, self.KEEP_5m)
        self.ts_lost = PercentCounterUnsafe(self.KEEP_15s, self.KEEP_5m)
        self.ts_rtt = AvgSummaryUnsafe(self.KEEP_15s, self.KEEP_5m)
        self.ts_outoforder_recv = PercentCounterUnsafe(self.KEEP_15s, self.KEEP_5m)
        

    def sent_ping(self, ttime: float, pktid: int, txlen: int):
        self.ts_ping_sent.record()

    def recv_ping(self, rtime: float, pktid: int, sip: str, sport: int):
        self.ts_ping_recv.record()

    def recv_pong(self, rtime: float, pktid: int, sip: str, sport: int, txip: str, txtime: int):
        self.ts_rtt.record(1000*(rtime - txtime))
        self.ts_pong_recv.record(1, self.ts_ping_sent)
        
        if pktid < self.last_rx_pktid and (pktid + 100000) > self.last_rx_pktid:
            logging.debug(f"OutOfOrder: pktid={pktid} last_rx_pktid={self.last_rx_pktid}")
            self.ts_outoforder_recv.record(1, self.ts_ping_sent)
        else:
            self.last_rx_pktid = pktid

    def recv_malformed(self, rtime: float, sip: str, sport: int):
        self.ts_corrupt_recv.record(1, self.ts_ping_sent)

    def timeout(self, pktid: int, tip: str):
        self.ts_lost.record(1, self.ts_ping_sent)

    def update_stats(self) -> bool: # return whether the object should be cleared (saw only zeros for long time in all vital counters)
        t = time.time()
        self.ts_ping_sent.aggregate(t)
        self.ts_ping_recv.aggregate(t)
        self.ts_pong_recv.aggregate(t, self.ts_ping_sent)
        self.ts_corrupt_recv.aggregate(t, self.ts_ping_sent)
        self.ts_lost.aggregate(t, self.ts_ping_sent)
        self.ts_rtt.aggregate(t)
        self.ts_outoforder_recv.aggregate(t, self.ts_ping_sent)
        
        return self.ts_ping_sent.is_inactive() and self.ts_ping_recv.is_inactive() and self.ts_pong_recv.is_inactive() and self.ts_corrupt_recv.is_inactive()
        
    def is_alarm(self) -> bool:
        if len(self.ts_lost.sum_15s) > 0 and self.ts_lost.sum_15s[-1][1] > 0:
            return True
        if len(self.ts_outoforder_recv.sum_15s) > 0 and self.ts_outoforder_recv.sum_15s[-1][1] > 0:
            return True
        if len(self.ts_corrupt_recv.sum_15s) > 0 and self.ts_corrupt_recv.sum_15s[-1][1] > 0:
            return True
        return False
    
    def get_ui_row(self):
        "return (name:str, ip:str, ping_sent: int, pong_recv:str, rtt:str, loss_total: int, outoforder_total:int, corrupt_total:int, ping_recv: str, alarm: bool)"
        return (self.name, humanize_ip(self.ip), self.ts_ping_sent.get_printable(), self.ts_pong_recv.get_printable(), self.ts_rtt.get_printable(), self.ts_lost.total, self.ts_outoforder_recv.total, self.ts_corrupt_recv.total, self.ts_ping_recv.total, self.is_alarm())
        
    def get_prometheus_metrics(self):
        tags = {'peerip':self.ip,'peer':self.name,'proto':self.proto}
        return [self.ts_ping_sent.get_prometheus_data('ping_sent', tags),
               self.ts_ping_recv.get_prometheus_data('ping_recv', tags),
               self.ts_pong_recv.get_prometheus_data('pong_recv', tags),
               self.ts_lost.get_prometheus_data('pong_lost', tags),
               self.ts_corrupt_recv.get_prometheus_data('corrupted_recv', tags),
               self.ts_outoforder_recv.get_prometheus_data('outoforder', tags),
               self.ts_rtt.get_prometheus_data('rtt', tags)]
        
    def get_report_data(self):
        return copy.deepcopy({'target_name': self.name, 'sock_remote_ip': self.ip, 'remote_ip': humanize_ip(self.ip) } | self.ts_ping_sent.get_report_data('ping_sent') | self.ts_ping_recv.get_report_data('ping_recv') | 
                             self.ts_pong_recv.get_report_data('pong_recv') | self.ts_lost.get_report_data('lost') | self.ts_corrupt_recv.get_report_data('corrupt_recv') |
                             self.ts_outoforder_recv.get_report_data('outoforder_recv') | self.ts_rtt.get_report_data('rtt'))


class UDPPing:
    STATS_INTERVAL_SEC = 15
    DEFAULT_PKT_LEN = 100

    HEADER = struct.Struct('!cxxxQII') # [type: byte, pad, pad, pad, pktid: ulonglong, len: uint]
    MAX_PKTID = (2**64)-1
    PKT_TYPE_PING = b'P'
    PKT_TYPE_PONG = b'R'

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
    def decode_packet(cls, data: bytes) -> Tuple[str, int, int, bool]: # op, pktid, len, data_corrupted
        op, pktid, plen, rcsum = cls.HEADER.unpack_from(data)
        data = data[cls.HEADER.size:]
        if len(data) != plen or cls.csum(data) != rcsum:
            return op, pktid, data, True
        else:
            return op, pktid, data, False

    @classmethod
    def gen_pong(cls, pid, data):
        return cls.HEADER.pack(cls.PKT_TYPE_PONG, pid, len(data), cls.csum(data)) + data



    lock: threading.Lock
    stop: threading.Event
    recvqueue: queue.Queue
    listen_ipaddr: str
    port: int
    timeout_sec: int
    txlen: int

    status: Dict[str, UDPPingHostData]
    pending: Dict[int,Tuple[str, float]] # {pktid: (ipaddress, send_time)}
    last_pktid: int

    targets: Dict[str,str] # { ipaddresses : name }
    interval: float

    t_recv: threading.Thread =None
    t_initiator: threading.Thread =None
    t_rxproc: threading.Thread =None
    t_periodic: threading.Thread =None


    def __init__(self, listen_ipaddr: str, port: int, interval: float =0.2, timeout_sec: float =5):
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.recvqueue = queue.Queue()
        self.listen_ipaddr = listen_ipaddr
        self.port = port
        self.status = {}
        self.pending = {}
        self.last_pktid = 0
        self.targets = {}
        self.interval = interval
        self.timeout_sec = timeout_sec
        self.txlen = self.DEFAULT_PKT_LEN

        #self.proto = 4 if ipaddress.ip_address(ip).ipv4_mapped != None else 6

    def set_targets(self, tgts: Dict[str,str]): # {ipaddress: name}
        with self.lock:
            self.target = {}
            for t in tgts:
                if ipaddress.ip_address(t).version == 4:
                    self.targets['::ffff:'+str(t)] = tgts[t]
                else:
                    self.targets[str(t)] = tgts[t]


    def set_txlen(self, txlen=100):
        self.txlen = txlen

    def _gen_pktid_unsafe(self):
        self.last_pktid += 1
        if self.last_pktid >= self.MAX_PKTID:
            self.last_pktid = 0
        return self.last_pktid
        
    
    def _receiver_loop(self):
        try:
            logging.debug("_receiver_loop up")
            while not self.stop.isSet():
                try:
                    data, addr = self.sock.recvfrom(65535)
                except TimeoutError:
                    continue
            
                rtime = time.perf_counter()

                sip, sport, _, _ = addr
                try:
                    op, pktid, payload, corrupted = self.decode_packet(data)
                except Exception as e:
                    logging.exception(f"Can not decode packet from {sip}")
                    self.recvqueue.put((rtime, sip, sport, None, None, True))
                    continue
                
                if op == self.PKT_TYPE_PING:
                    self.sock.sendto(self.gen_pong(pktid, payload), (sip, sport))

                self.recvqueue.put((rtime, sip, sport, op, pktid, corrupted))
        except:
            logging.exception("_receiver_loop exception:")
            raise

    def _pkt_processor_loop(self):
        try:
            logging.debug("_pkt_processor_loop up")
            while not self.stop.isSet():
                try:
                    rtime, sip, sport, op, pktid, corrupted = self.recvqueue.get(timeout=1)
                except queue.Empty:
                    continue

                with self.lock:
                    if not sip in self.status:
                        self.status[sip] = UDPPingHostData(sip, self.targets.get(sip, "only-rx"))

                    if corrupted:
                        self.status[sip].recv_malformed(rtime, sip, sport)
                        if pktid != None:
                            self.pending.pop(pktid, None)
                    elif op == self.PKT_TYPE_PING:
                        self.status[sip].recv_ping(rtime, pktid, sip, sport)
                    elif op == self.PKT_TYPE_PONG:
                        txip, txtime = self.pending.pop(pktid, (None,None))
                        self.status[sip].recv_pong(rtime, pktid, sip, sport, txip, txtime)
                    else:
                        self.status[sip].recv_malformed(rtime, sip, sport)

                self.recvqueue.task_done()
        except:
            logging.exception("_pkt_processor_loop exception:")
            raise

    def _initiator_loop(self):
        logging.debug("_initiator_loop up")
        while not self.stop.isSet():
            try:
                with self.lock:
                    for dip in self.targets:
                        if not dip in self.status:
                            self.status[dip] = UDPPingHostData(dip, self.targets[dip])
                        pktid = self._gen_pktid_unsafe()
                        txtime = time.perf_counter()
                        self.pending[pktid] = (dip, txtime)

                        self.sock.sendto(self.gen_ping(pktid, self.txlen, False),(dip, self.port))

                        self.status[dip].sent_ping(txtime, pktid, self.txlen)

                time.sleep(self.interval)
            except OSError:
                logging.exception("_initiator_loop will recover in 5 sec from exception:")
                time.sleep(5)
            except:
                logging.exception("_initiator_loop exception:")
                raise

    def _periodic_loop(self):
        try:
            logging.debug("_periodic_loop up")
            last_t = time.time()
            while not self.stop.isSet():
                time.sleep(1)

                t = time.perf_counter()
                remove_pktids = []
                remove_stats = []
                with self.lock:
                    for pktid in self.pending:
                         txip, txtime = self.pending[pktid]
                         if t > txtime + self.timeout_sec:
                             self.status[txip].timeout(pktid, txip)
                             remove_pktids.append(pktid)
                    for rpktid in remove_pktids:
                        self.pending.pop(rpktid, None)
                    
                    if time.time() < last_t + self.STATS_INTERVAL_SEC:
                        continue
                    else:
                        last_t = time.time()
                    # run the rest only every STATS_INTERVAL_SEC
                    for s in self.status:
                        if self.status[s].update_stats():
                            remove_stats.append(s)
                    for rs in remove_stats:
                        self.status.pop(s, None)

                logging.debug(f"udpping state: last_pktid: {self.last_pktid} status_length: {len(self.status)} stop: {self.stop.isSet()} initiator_alive: {self.t_initiator.is_alive()} recv_alive: {self.t_recv.is_alive()} rxproc_alive: {self.t_rxproc.is_alive()} periodic_alive: {self.t_periodic.is_alive()}")
        except:
            logging.exception("_peridic_loop exception:")
            raise


    def start(self) -> None:
        logging.debug("UDPPing starting up")
        self.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        self.sock.settimeout(1)
        self.sock.bind((self.listen_ipaddr, self.port))

        self.t_recv = threading.Thread(target=self._receiver_loop)
        self.t_recv.start()

        self.t_initiator = threading.Thread(target=self._initiator_loop)
        self.t_initiator.start()

        self.t_rxproc = threading.Thread(target=self._pkt_processor_loop)
        self.t_rxproc.start()

        self.t_periodic = threading.Thread(target=self._periodic_loop)
        self.t_periodic.start()
        logging.debug("UDPPing up and running")

    def terminate(self) -> None:
        logging.debug("udpping stop called")
        self.stop.set()
        self.t_initiator.join()
        logging.debug("joined t_initiator")
        self.t_recv.join()
        logging.debug("joined t_recv")
        
        self.sock.close()

        self.t_rxproc.join()
        logging.debug("joined t_rxproc")
        self.t_periodic.join()
        logging.debug("joined t_periodic")
    
    def get_ui_rows(self, offset: int =0, limit: int =None): #-> List[Tuple[...]]:
        with self.lock:
            ks = sorted(list(self.status.keys()))
            if limit and offset+limit < len(ks):
                ks = ks[offset:offset+limit]
            else:
                ks = ks[offset:]
            for s in ks:
                yield self.status[s].get_ui_row()
    
    def get_report(self):
        with self.lock:
            return {'udpping': {'results' : [self.status[s].get_report_data() for s in self.status], 'tx_data_length_bytes' : self.txlen, 'tx_gap_sec' : self.interval}}
    
    def get_prometheus_metrics(self):
        m = []
        with self.lock:
            for k in self.status:
                m += self.status[k].get_prometheus_metrics()
        logging.debug(f"udpping get_prometheus_metrics returning {len(m)} elements")
        return m
