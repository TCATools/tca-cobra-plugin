# -*- coding: utf-8 -*-

"""
    cli
    ~~~

    Implements CLI mode

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/WhaleShark-Team/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2018 Feei. All rights reserved
"""
import re
import os

from .engine import scan, Running
from .exceptions import PickupException
from .export import write_to_file
from .log import logger
from .rule import Rule
from .utils import ParseArgs
from .utils import md5, random_generator


def get_sid(target):
    target = target
    sid = md5(target)[:5]
    pre = 's'
    sid = '{p}{sid}{r}'.format(p=pre, sid=sid, r=random_generator())
    return sid.lower()


def start(target, formatter, output, special_rules, scan_list_file=None):
    """
    Start CLI
    :param target: File, FOLDER, GIT
    :param formatter:
    :param output:
    :param special_rules:
    :param scan_list_file: scan file list path, one file path per line
    :return:
    """
    # generate single scan id
    s_sid = get_sid(target)

    # parse target mode and output mode
    pa = ParseArgs(target, formatter, output, special_rules)

    # target directory
    try:
        target_directory = pa.target_directory()
        logger.info('[CLI] Target directory: {d}'.format(d=target_directory))

        languages = Rule().languages
        files = []
        if languages is not None:
            # 收集 languages.xml 中所有语言的后缀
            all_extensions = set()
            for _, lang_info in languages.items():
                all_extensions.update(lang_info['extensions'])
            logger.info('Auto generating scan file list by languages.xml extensions: {e}'.format(
                e=','.join(sorted(all_extensions))))
            for dirpath, dirs, filenames in os.walk(target_directory):
                for f in filenames:
                    if f.endswith(tuple(all_extensions)):
                        files.append(os.path.join(dirpath, f))
            logger.info(f"Find files: {len(files)}")
        if not files:
            logger.info("Files is None.")
            exit()
        # 解析扫描文件列表
        scan_file_list = []
        if scan_list_file is not None:
            try:
                with open(scan_list_file, 'r') as f:
                    for line in f.readlines():
                        line = line.strip()
                        if line and not line.startswith('#') and line in files:
                            scan_file_list.append(line)
                logger.info('Loaded {c} files from scan list'.format(c=len(scan_file_list)))
            except Exception as e:
                logger.critical('Failed to load scan list file: {f}, error: {e}'.format(f=scan_list_file, e=str(e)))
                exit()
        else:
            # 如果未指定扫描文件列表，则根据 languages.xml 中所有语言的后缀自动生成
            scan_file_list = files
        
        if len(scan_file_list) == 0:
            exit()

        if pa.special_rules is not None:
            logger.info('[CLI] [SPECIAL-RULE] only scan used by {r}'.format(r=','.join(pa.special_rules)))
        # scan
        scan(target_directory=target_directory, s_sid=s_sid, special_rules=pa.special_rules,
             scan_file_list=scan_file_list)

    except PickupException:
        result = {
            'code': 1002,
            'msg': 'Repository not exist!'
        }
        Running(s_sid).data(result)
        logger.critical('Repository or branch not exist!')
        exit()
    except Exception:
        result = {
            'code': 1002,
            'msg': 'Exception'
        }
        Running(s_sid).data(result)
        raise

    write_to_file(target=target, sid=s_sid, output_format=formatter, filename=output)
