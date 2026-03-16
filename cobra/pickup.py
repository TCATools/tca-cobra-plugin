# -*- coding: utf-8 -*-

"""
    pickup
    ~~~~~~

    Implements pickup git/compress file

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/WhaleShark-Team/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2018 Feei. All rights reserved
"""
from .log import logger


class File(object):
    def __init__(self, file_path):
        self.file_path = file_path

    def read_file(self):
        """
        读取文件内容
        :return:
        """
        f = open(self.file_path, 'r').read()
        return f

    def lines(self, line_rule):
        """
        获取指定行内容
        :param line_rule: sed 风格的行范围规则，如 "10,20p" 表示第10行到第20行
        :return: 指定行范围的文本内容，失败或为空时返回 False
        """
        # 解析 sed 风格的行范围规则，支持 "Np" (单行) 和 "N,Mp" (范围) 格式
        import re
        match = re.match(r'^(\d+)(?:,(\d+))?p$', line_rule.strip())
        if not match:
            logger.critical('[PICKUP] 无法解析行规则: {rule}'.format(rule=line_rule))
            return False

        start = int(match.group(1))
        end = int(match.group(2)) if match.group(2) else start

        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                selected_lines = []
                for line_number, line in enumerate(f, 1):
                    if line_number > end:
                        break
                    if start <= line_number <= end:
                        selected_lines.append(line)
            if selected_lines:
                return ''.join(selected_lines)
            else:
                return False
        except IOError as e:
            logger.critical('[PICKUP] {err}'.format(err=e))
            return False
