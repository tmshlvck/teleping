#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import click
import sys
import os

import telephant.basic


@click.command("Telephant is your best friend")
@click.option('-c', '--config', 'config_file', default=os.environ.get('TELEPHANT_CONFIG','~/.telephant.yml'), help="ovrride TELEPHANT_CONFIG env or defult ~/.telephant.yml")
@click.option('-t', '--target', 'tgts', multiple=True, help="target IP or hostname")
@click.option('-d', '--daemon', 'daemon', is_flag=True, help="disable Rich UI, output log to console")
def main(config_file, tgts, daemon):
    telephant.basic.main(config_file, tgts, not daemon)

if __name__ == '__main__':
    sys.exit(main())
