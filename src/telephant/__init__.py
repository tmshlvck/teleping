#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import click
import sys
import os
import logging

from telephant.common import TelephantCore
from telephant.udpping import UDPPing
from telephant.webui import start_webui

from prometheus_client.core import REGISTRY


@click.command("Telephant is your best friend")
@click.option('-c', '--config', 'config_file', default=os.environ.get('TELEPHANT_CONFIG','~/.telephant.yml'), help="override TELEPHANT_CONFIG env or defult ~/.telephant.yml")
@click.option('-d', '--debug', 'debug', is_flag=True, help="Enable debugging log messages")
def main(config_file, debug):
    tc = TelephantCore(os.path.expanduser(config_file))
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
