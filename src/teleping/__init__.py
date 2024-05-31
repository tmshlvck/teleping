#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Telephant Ping

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

import click
import sys
import os
import logging

from teleping.udpping import UDPPing
from teleping.webui import start_webui
from teleping.config import Config, read_config

from prometheus_client.core import REGISTRY


class TelepingCore:
    cfg_filename: str
    cfg: Config
    udpping: UDPPing

    def __init__(self, cfg_filename: str):
        self.cfg_filename = cfg_filename
        self.cfg = read_config(self.cfg_filename)

    def start(self):
        logging.info("Config read, logging initialized, starting udp responder and initiator.")
        self.udpping = UDPPing()
        self.udpping.start(self.cfg.udpping.bind_address4, self.cfg.udpping.bind_address6, self.cfg.udpping.port, self.cfg.udpping.interval)
        self.udpping.set_targets({t.addr: str(t.name if t.name else (t.host if t.host else t.addr)) for t in self.cfg.normalized_targets})

    def shutdown(self):
        logging.info("Shutting down udp ping.")
        self.udpping.stop()

    def reconfig(self):
        logging.info("Reconfig in progress...")
        self.cfg = read_config(self.cfg_filename)
        self.udpping.set_targets([t.addr for t in self.cfg.normalized_targets])
        logging.info("Reconfig finished.")
        


@click.command("Telephant Ping is your best friend")
@click.option('-c', '--config', 'config_file', default=os.environ.get('TELEPING_CONFIG','~/.teleping.yml'), help="override TELEPING_CONFIG env or defult ~/.teleping.yml")
@click.option('-d', '--debug', 'debug', is_flag=True, help="Enable debugging log messages")
def main(config_file, debug):
    tc = TelepingCore(os.path.expanduser(config_file))
    if debug:
        tc.cfg.debug = True

    if tc.cfg.log_file:
        logging.basicConfig(level=(logging.DEBUG if tc.cfg.debug else logging.INFO),
                            format='%(asctime)s %(levelname)s %(message)s',
                            filename=tc.cfg.log_file)
    else:
        logging.basicConfig(level=(logging.DEBUG if tc.cfg.debug else logging.INFO),
                            format='%(asctime)s %(levelname)s %(message)s')

    tc.start()

    logging.info("Starting Prometheus")
    REGISTRY.register(tc.udpping)

    logging.info("Starting web ui.")
    start_webui(tc)
    
    
if __name__ == '__main__':
    sys.exit(main())
