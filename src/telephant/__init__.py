#!/usr/bin/python3
# -*- coding: utf-8 -*-

import click
import sys
import os
import yaml
import logging
import socket
import datetime
import ipaddress
import requests

import telephant.traceroute
import telephant.ping
import telephant.basic

from typing import Tuple, Dict, Any


def resolve_host(host: str, afi: int|None =None): #-> List[IPv4Addres|IPv6Address]:
    result = set()
    for testafi in [4,6]:
        if afi==testafi or afi == None:
            try:
                for family, type, proto, canonname, sockaddr in socket.getaddrinfo(host, None, socket.AF_INET if testafi == 4 else socket.AF_INET6):
                    #print(f"DEBUG: family={str(family)} type={str(type)} proto={str(proto)} canonname={str(canonname)} sockaddr={str(sockaddr)}")
                    result.add(ipaddress.ip_address(sockaddr[0]))
            except socket.gaierror:
                pass
    return result

def normalize_targets(tgts):
    def check_afi(tgt):
        if tgt.get('afi',None) in [4,6]:
            return True
        else:
            return False
    
    def check_ipaddress(tgt):
        if not 'ipaddress' in tgt:
            return False
        if isinstance(tgt['ipaddress'], ipaddress.IPv4Address) or isinstance(tgt['ipaddress'], ipaddress.IPv6Address):
            return True
        else:
            return False

    for t in tgts:
        if not isinstance(t, dict):
            t = {'host': str(t)}
        if not 'host' in t:
            continue
        if not 'name' in t:
            t['name'] = t['host']
        if check_afi(t) and check_ipaddress(t):
            return t
        else:
            for ip in resolve_host(t['host'], int(t['afi']) if t.get('afi', None) != None else None):
                yield {'host': t['host'], 'afi': ip.version, 'name': t['name'], 'ipaddress': ip}

def format_report(report_struct: Dict[str, Any]) -> str:
    yaml.SafeDumper.org_represent_str = yaml.SafeDumper.represent_str
    def repr_str(dumper, data):
        if '\n' in data:
            return dumper.represent_scalar(u'tag:yaml.org,2002:str', data, style='|')
        return dumper.org_represent_str(data)
    yaml.add_representer(str, repr_str, Dumper=yaml.SafeDumper)

    def ipaddress_representer(dumper, data):
        return dumper.represent_scalar(u'tag:yaml.org,2002:str', str(data))
    yaml.add_representer(ipaddress.IPv4Address, ipaddress_representer, Dumper=yaml.SafeDumper)
    yaml.add_representer(ipaddress.IPv6Address, ipaddress_representer, Dumper=yaml.SafeDumper)

    return yaml.dump(report_struct, Dumper=yaml.SafeDumper)


def send_report(server_url: str, server_token: str, group: int, report: str):
    logging.debug(f"Sending report to {server_url} to group {group}")
    try:
        response = requests.post(requests.compat.urljoin(server_url, 'report'), headers={'X-API-Key': server_token}, json={'report':str(report)})
        if response.status_code == 201:
            logging.debug(f"Received response code: {response.status_code} result: {response.json()}")
        else:
            logging.error(f"Received response code: {response.status_code} result: {response.json()}")

        return response.json()
    except Exception as e:
        logging.exception("Report submission failed:")


def emit_report(config: Dict[str,Any], telephant_server: str, telephant_token: str, data: Dict[str,Any] = {}) -> None:
    start_time = datetime.datetime.now()
    report = data.copy()
    report['start_local'] = str(start_time.astimezone())
    report['start_timestamp'] = start_time.timestamp()

    # Collect basic data:
    report['targets'] = config['targets']
    # ip link
    report['basic_ip_link'] = telephant.basic.ip_link(config)
    # ip address
    report['basic_ip_address'] = telephant.basic.ip_address(config)
    report['host_ip_address'] = telephant.basic.ip_address_parse(config)
    # ip route + ip -6 route
    report['basic_ip_route'] = telephant.basic.ip_route(config, afi=4)
    report['basic_ip_route6'] = telephant.basic.ip_route(config, afi=6)
    
    # ping all targets v4+v6
    report['ping'] = {}
    for t in config['targets']:
        tip = str(t['ipaddress'])
        report['ping'][tip] = telephant.ping.linux_ping(config, tip, afi=t['afi'])

    # traceroute all targets v4+v6
    report['traceroute'] = {}
    traceroute_hops = set()
    for t in config['targets']:
        tip = str(t['ipaddress'])
        report['traceroute'][tip],hips = telephant.traceroute.linux_traceroute(config, tip, afi=t['afi'])
        traceroute_hops |= hips
    report['traceroute_seen_hops'] = [str(hip) for hip in traceroute_hops]

    # TODO
    # API: report IPs, pings and traceroutes and get peers if enabled
    # start udp

    end_time = datetime.datetime.now()
    report |= {'end_local': str(end_time.astimezone()), 'end_timestamp': end_time.timestamp()}

    # TODO
    # repeat every period (1 hour default): run basic collection again (using updated list of targets), report basic collection + UDPsmoke results

    if telephant_server:
        res = send_report(telephant_server, telephant_token, None, format_report(report))
        print(str(res))
    elif config.get('telephant',{}).get('server', None):
        res = send_report(config.get('telephant',{}).get('server', None), config.get('telephant',{}).get('token', None), config.get('telephant',{}).get('group', None), format_report(report))
        print(str(res))
    else:
        print(format_report(report))


@click.command("Telephant is your best friend")
@click.option('-c', '--config', 'config_file', default=os.environ.get('TELEPHANT_CONFIG','.telephant.yml'), help="ovrride TELEPHANT_CONFIG env or defult .telephant.yml")
@click.option('-t', '--target', 'tgts', multiple=True, help="target IP or hostname")
@click.option('-r', '--run', 'run_tests', multiple=True, help="tests to run (basic,udpsmoke,tcpdrill,passive)")
@click.option('-p', '--period', 'period', default='3600', help="reporting period (in seconds)")
@click.option('-s' '--server', 'telephant_server', help="URL of the telephant server")
@click.option('-a' '--authtoken', 'telephant_token', help="API token for telephant server")
def main(config_file, tgts, run_tests, period, telephant_server, telephant_token):
    config = {}
    try:
        with open(config_file, 'r') as cfd:
            config = yaml.load(cfd, Loader=yaml.Loader)
    except Exception as e:
        logging.exception("Config file load failed. Continuing with defaults.")

    # Collect targets
    if not 'targets' in config:
        config['targets'] = []
    config['targets'] += tgts
    config['targets'] = list(normalize_targets(config['targets']))

    emit_report(config, telephant_server, telephant_token, {})

if __name__ == '__main__':
    sys.exit(main())
