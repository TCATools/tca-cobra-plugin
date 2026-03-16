# -*- coding: utf-8 -*-

"""
Cobra Main
"""
import time
import argparse
import logging
import traceback
from .log import logger
from . import cli

from .__version__ import __title__, __introduction__, __url__, __version__
from .__version__ import __author__, __author_email__, __license__
from .__version__ import __copyright__, __epilog__


def main():
    try:
        # arg parse
        t1 = time.time()
        parser = argparse.ArgumentParser(prog=__title__, description=__introduction__, epilog=__epilog__, formatter_class=argparse.RawDescriptionHelpFormatter)

        parser_group_scan = parser.add_argument_group('Scan')
        parser_group_scan.add_argument('-t', '--target', dest='target', action='store', default='', metavar='<target>', help='target directory')
        parser_group_scan.add_argument('-f', '--format', dest='format', action='store', default='json', metavar='<format>', choices=['json'], help='vulnerability output format (formats: %(choices)s)')
        parser_group_scan.add_argument('-o', '--output', dest='output', action='store', default='', metavar='<output>', help='vulnerability output STREAM, FILE, HTTP API URL, MAIL')
        parser_group_scan.add_argument('-r', '--rule', dest='special_rules', action='store', default=None, metavar='<rule_id>', help='specifies rules e.g: CVI-100001,cvi-190001')
        parser_group_scan.add_argument('-d', '--debug', dest='debug', action='store_true', default=False, help='open debug mode')
        parser_group_scan.add_argument('-sl', '--scan-list', dest='scan_list', action='store', default=None, metavar='<scan_list>', help='scan file list path, one file path per line, only scan files in the list')

        args = parser.parse_args()

        if args.debug:
            logger.setLevel(logging.DEBUG)
            logger.debug('[INIT] set logging level: debug')

        if args.target == '' and args.output == '':
            parser.print_help()
            exit()

        logger.debug('[INIT] start scanning...')

        cli.start(args.target, args.format, args.output, args.special_rules, args.scan_list)
        t2 = time.time()
        logger.info('[INIT] Done! Consume Time:{ct}s'.format(ct=t2 - t1))

    except Exception as e:
        exc_msg = traceback.format_exc()
        logger.warning(exc_msg)


if __name__ == '__main__':
    main()
