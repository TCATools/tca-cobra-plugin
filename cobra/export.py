# -*- coding: utf-8 -*-

"""
    export
    ~~~~~~

    Export scan result to files or console

    :author:    40huo <git@40huo.cn>
    :homepage:  https://github.com/WhaleShark-Team/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2018 Feei. All rights reserved
"""
import json
import os

from .config import running_path
from .log import logger


def dict_to_json(dict_obj):
    """
    Convert scan result to JSON string.
    :param dict_obj: a dict object
    :return: JSON String
    """
    return json.dumps(dict_obj, ensure_ascii=False)


def write_to_file(target, sid, output_format='', filename=None):
    """
    Export scan result to file.
    :param target: scan target
    :param sid: scan sid
    :param output_format: output format
    :param filename: filename to save
    :return:
    """
    if not filename:
        logger.debug('[EXPORT] No filename given, nothing exported.')
        return False

    scan_data_file = os.path.join(running_path, '{sid}_data'.format(sid=sid))
    with open(scan_data_file, 'r') as f:
        scan_data = json.load(f).get('result')

    scan_data['target'] = target

    if output_format == 'json' or output_format == 'JSON':
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json_data = {
                    sid: scan_data,
                }
                f.write(dict_to_json(json_data))
        except IOError:
            logger.warning('[EXPORT] Please input a file path after the -o parameter')
            return False

    else:
        logger.warning('[EXPORT] Unknown output format.')
        return False

    return True
