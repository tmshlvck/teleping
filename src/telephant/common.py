# coding: utf-8
"""
Telephant common module

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

import sys
import os
import subprocess
import shutil
import traceback
import json
import ipaddress
import yaml
import logging
import datetime
import socket
import requests
import threading
import time

from typing import Any, Dict, List, Tuple, Set, Iterator
from ipaddress import IPv4Address, IPv6Address, ip_address

from telephant.udpping import UDPPing
from telephant.config import Config, read_config


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





class TelephantCore:
    cfg_filename: str
    cfg: Config
    udpping: UDPPing

    __slots__ = tuple(__annotations__)

    def __init__(self, cfg_filename: str):
        self.cfg_filename = cfg_filename
        self.cfg = read_config(self.cfg_filename)


#class TelephantState:
#    config_file: str
#    cmdline_tgts: List[str]
#    config: Dict[str, Any]
#    state: str
#    lock: threading.Lock
#    stop: threading.Event
#    display_scroll: int
#    scroll_size: int
#    starttime: datetime.datetime
#    display_log: bool
#    udpping: telephant.udpping.UDPPing
#
#    __slots__ = tuple(__annotations__)
#
#    STATE_HELP = "q:Quit u:up d:down c:reConfig r:send Report l: Logs +/-: TxLen+/-"
#
#    def __init__(self, config_file: str, cmdline_tgts: List[str]):
#        self.config_file = config_file
#        self.cmdline_tgts = cmdline_tgts
#        self.config = None
#        self.state = ""
#        self.lock = threading.RLock()
#        self.stop = threading.Event()
#        self.display_scroll = 0
#        self.scroll_size = 30
#        self.display_log = False
#        self.starttime = datetime.datetime.now()
#        self.udpping = None
#
#    def load_config(self):
#        config = {}
#        try:
#            with open(os.path.expanduser(self.config_file), 'r') as cfd:
#                config = yaml.load(cfd, Loader=yaml.Loader)
#        except Exception as e:
#            logging.exception("Config file load failed. Continuing with defaults.")
#        
#        self.config = config
#        self._refresh_targets()
#
#    @staticmethod
#    def _normalize_targets(tgts: List[Any]) -> Dict[str, Any]:
#        def check_afi(tgt):
#            if tgt.get('afi',None) in [4,6]:
#                return True
#            else:
#                return False
#
#        def check_ipaddress(tgt):
#            if not 'ipaddress' in tgt:
#                return False
#            if isinstance(tgt['ipaddress'], ipaddress.IPv4Address) or isinstance(tgt['ipaddress'], ipaddress.IPv6Address):
#                return True
#            else:
#                return False
#
#        for t in tgts:
#            if not isinstance(t, dict):
#                t = {'host': str(t)}
#            if not 'host' in t:
#                continue
#            if not 'name' in t:
#                t['name'] = t['host']
#            if check_afi(t) and check_ipaddress(t):
#                return t
#            else:
#                for ip in resolve_host(t['host'], int(t['afi']) if t.get('afi', None) != None else None):
#                    yield {'host': t['host'], 'afi': ip.version, 'name': t['name'], 'ipaddress': ip}
#
#    def _refresh_targets(self):
#        # Collect targets
#        if not self.config.get('targets', None):
#            self.config['targets'] = []
#        self.config['targets'] += self.cmdline_tgts
#        self.config['targets'] = list(self._normalize_targets(self.config['targets']))
#
#    def elapsed_str(self):
#        d = datetime.datetime.now() - self.starttime
#        d -= datetime.timedelta(microseconds=d.microseconds) # chop microseconds
#        return str(d)
#    
#    def elapsed_sec(self):
#        return (datetime.datetime.now() - self.starttime).total_seconds()
#    
#    def format_state(self):
#        return f"{self.elapsed_str()} | Tx {self.udpping.txlen+self.udpping.HEADER.size if self.udpping else '-'}B | [bold]{self.state if self.state else '---'}[/bold] | {self.STATE_HELP}"
#        
#    def get_prometheus_metrics(self):
#        m = [telephant.prometheus.Counter('runtime', self.elapsed_sec(), {})]
#        if self.udpping:
#            return m + self.udpping.get_prometheus_metrics()
#        else:
#            return m
#
#
#
#def _ui_displayloop(state: TelephantState, freq: int =1):
#    logging.debug("ui up")
#
#    from rich.console import Console
#    from rich.table import Table
#    from rich.live import Live
#    from rich.layout import Layout
#    from rich.panel import Panel
#
#    console = Console()
#    layout = Layout()
#    layout.split_column(Layout("", name="upper"), Layout(Panel("Status: ready"), name="lower"))
#    layout["lower"].size = 3
#    layout["upper"].update(Panel(""))
#    layout["lower"].update(Panel(""))
#    
#    with Live(layout, refresh_per_second=freq, screen=True, console=console):
#        while not state.stop.isSet():
#            if state.display_log:
#                table = Table(title="Logs", expand=True, row_styles=["dim", ""], show_edge=False, show_header=False)
#                #table.add_column("Time", style="white", no_wrap=True)
#                table.add_column("Log message", style="white", no_wrap=False)
#                for l in buffering_handler.buffer:
#                    table.add_row(formatter.format(l))
#
#            else:
#                table = Table(title="UDPPing", expand=True, row_styles=["dim", ""], show_edge=False)
#                table.add_column("Peer")
#                table.add_column("Tx")
#                table.add_column("Rx")
#                table.add_column("RTT (ms)")
#                table.add_column("Lost OoO Crpt")
#                table.add_column("PingRx")
#                #table.add_column("Status", justify="right", style="magenta")
#                
#                if state.udpping:
#                    for name, ip, ping_sent, pong_recv, rtt, loss, outoforder_recv, corrupt_recv, ping_rx_total, alarm in state.udpping.get_ui_rows(state.display_scroll, console.size.height - 4):
#                        if alarm:
#                            table.add_row(name + ' ' + str(ip), ping_sent, pong_recv, rtt, f"{loss} {outoforder_recv} {corrupt_recv}", f"{ping_rx_total}", style="red")
#                        else:
#                            table.add_row(name + ' ' + str(ip), ping_sent, pong_recv, rtt, f"{loss} {outoforder_recv} {corrupt_recv}", f"{ping_rx_total}")
#            
#            layout["upper"].update(table)
#
#            with state.lock:
#                layout["lower"].update(Panel(state.format_state()))
#
#            time.sleep(1/freq)  # arbitrary delay
#
#
#def terminate(state: TelephantState):
#    state.stop.set()
#    with state.lock:
#        if state.udpping:
#            state.udpping.terminate()
#            state.udpping = None
#
#
#def reconfig(state: TelephantState):
#    state.load_config()
#
#    if state.config.get('emit_basic_report_and_exit', False):
#        res = telephant_emit_report(state.config, {})
#        logging.debug(f"Report sent: {str(res)}")
#        print(str(res))
#        terminate()
#        sys.exit()
#
#    if state.config.get('udpping', None):
#        if not state.udpping:
#            state.udpping = telephant.udpping.UDPPing(listen_ipaddr=state.config.get('udpping', {}).get("bind_address", "::"),
#                                                  port=state.config.get('udpping', {}).get("port", 9511),
#                                                  interval=state.config.get('udpping', {}).get("interval", 1))
#            if state.config.get('udpping',{}).get('tx_length'):
#                state.udpping.set_txlen(int(state.config['udpping']['tx_length']))
#            state.udpping.start()
#        
#        state.udpping.set_targets({t['ipaddress']: t['name'] for t in state.config['targets']})
#
#    if state.config.get('tcpdrill', None):
#        raise NotImplementedError
#
#
#def _ui_keyloop(state: TelephantState):
#    logging.debug("keyloop up")
#    import tty,termios
#
#    END_OF_TEXT = chr(3)  # CTRL+C (prints nothing)
#    END_OF_FILE = chr(4)  # CTRL+D (prints nothing)
#    CANCEL      = chr(24) # CTRL+X
#
#    orig_settings = termios.tcgetattr(sys.stdin)
#    tty.setcbreak(sys.stdin)
#    try:
#        while not state.stop.isSet():
#            k = sys.stdin.read(1)[0]
#            if k in {END_OF_TEXT, END_OF_FILE, CANCEL}:
#                state.state = "Terminating..."
#                terminate(state)
#                logging.debug("Termination triggered by ctrl+c")
#                raise KeyboardInterrupt
#            elif k == 'q':
#                state.state = "Terminating..."
#                logging.debug("Termination triggered by keyboard")
#                terminate(state)
#            elif k == 'c':
#                state.state = "Reconfig in progress..."
#                logging.debug("Reconfig triggered by keyboard")
#                reconfig(state)
#                state.state = "Reconfigured"
#            elif k == 'l':
#                state.display_log = not state.display_log
#            elif k == 'x':
#                state.state = "Test test test!!!"
#                logging.debug("TEst Test test")
#            elif k == '+':
#                if state.udpping:
#                    state.udpping.txlen += 1
#                    logging.debug(f"Tx Len set {state.udpping.txlen}")
#            elif k == '-':
#                if state.udpping:
#                    state.udpping.txlen -= 1
#                    logging.debug(f"Tx Len set {state.udpping.txlen}")
#            elif k == 'r':
#                state.state = "Sending report..."
#                logging.debug("Report send triggered by keyboard")
#                if state.udpping:
#                    rr = telephant_emit_report(state.config, state.udpping.get_report())
#                else:
#                    rr = telephant_emit_report(state.config, {})
#                if rr and 'report_url' in rr:
#                    state.state = f"Report: {rr['report_url']}"
#                else:
#                    state.state = 'Report failed. See log!'
#                logging.debug(f"Report sent: {str(rr)}")
#            elif k == 'u''':
#                if state.display_scroll > 0:
#                    state.display_scroll-=1
#            elif k == 'd':
#                state.display_scroll+=1
#            elif k == 'n':
#                if state.display_scroll < state.page_size:
#                    state.display_scroll=0
#            elif k == 'p':
#                state.display_scroll+=state.page_size
#            else:
#                state.state = f'Unknown command key "{k}"'
#    except:
#        logging.exception("keyboard_loop exception:")
#        raise
#    finally:
#        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, orig_settings) 
#        print()
#
#
#def main(config_file: str, cmdline_tgts: List[str], enable_ui: bool =True):
#    state = TelephantState(config_file, cmdline_tgts)
#
#    state.load_config()
#    if state.config.get('log_file', None):
#        lfh = logging.FileHandler(state.config.get('log_file'))
#        if state.config.get('debug', False):
#            lfh.setLevel(logging.DEBUG)
#        lfh.setFormatter(formatter)
#        log.addHandler(lfh)
#
#    reconfig(state)
#
#    t_prom = threading.Thread(target=telephant.prometheus.server_loop, args=(state.get_prometheus_metrics, "telephant", state.config.get('prometheus_exporter',{}).get('listen','::'),
#                                                                             int(state.config.get('prometheus_exporter',{}).get('port',9123))))
#    t_prom.daemon = True
#    t_prom.start()
#
#    if enable_ui:
#        log.addHandler(buffering_handler)
#
#        t_uiloop = threading.Thread(target=_ui_displayloop, args=(state,))
#        t_uiloop.start()
#        t_keyloop = threading.Thread(target=_ui_keyloop, args=(state,))
#        t_keyloop.start()
#    
#        t_uiloop.join()
#        logging.debug("t_uiloop joined")
#        t_keyloop.join()
#        logging.debug("t_keyloop joined")
#    else:
#        chandler = logging.StreamHandler(sys.stdout)
#        chandler.setLevel(logging.DEBUG)
#        chandler.setFormatter(formatter)
#        log.addHandler(chandler)
#        logging.debug("Running in batch mode")
#        try:
#            while True:
#                time.sleep(1)
#        except:
#            terminate(state)
#            raise
#