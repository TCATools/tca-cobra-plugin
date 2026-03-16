# -*- coding: utf-8 -*-

"""
cobra log
"""
import sys
import logging

logger = logging.getLogger('CobraLog')
sh_format = logging.Formatter("\r%(asctime)s-%(levelname)s: %(message)s", "%H:%M:%S")

sh = logging.StreamHandler(sys.stdout)
sh.setFormatter(sh_format)
logger.addHandler(sh)
logger.setLevel(logging.INFO)
