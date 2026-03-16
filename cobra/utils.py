# -*- coding: utf-8 -*-

"""
    utils
    ~~~~~

    Implements utils

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/WhaleShark-Team/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2018 Feei. All rights reserved
"""
import hashlib
import os
import random
import re
import string
import sys
import time

from .log import logger
from .__version__ import __version__, __python_version__, __platform__, __url__


class ParseArgs(object):
    def __init__(self, target, formatter, output, special_rules=None):
        self.target = target
        self.formatter = formatter
        self.output = output
        if special_rules is not None and special_rules != '':
            self.special_rules = []
            extension = '.xml'
            # check rule name
            s_rules = special_rules.split(',')
            for sr in s_rules:
                if self._check_rule_name(sr):
                    if extension not in sr:
                        sr += extension
                    self.special_rules.append(sr)
                else:
                    logger.critical('Exception rule name: {sr}'.format(sr=sr))

        else:
            self.special_rules = None

    @staticmethod
    def _check_rule_name(name):
        return re.match(r'^(cvi|CVI)-\d{6}(\.xml)?', name.strip()) is not None


    def target_directory(self):
        return os.path.abspath(self.target)


def to_bool(value):
    """Converts 'something' to boolean. Raises exception for invalid formats"""
    if str(value).lower() in ("on", "yes", "y", "true", "t", "1"):
        return True
    if str(value).lower() in ("off", "no", "n", "false", "f", "0", "0.0", "", "none", "[]", "{}"):
        return False
    raise Exception('Invalid value for boolean conversion: ' + str(value))


def convert_time(seconds):
    """
    Seconds to minute/second
    Ex: 61 -> 1'1"
    :param seconds:
    :return:
    :link: https://en.wikipedia.org/wiki/Prime_(symbol)
    """
    one_minute = 60
    minute = seconds / one_minute
    if minute == 0:
        return str(seconds % one_minute) + "\""
    else:
        return str(int(minute)) + "'" + str(seconds % one_minute) + "\""


def convert_number(n):
    """
    Convert number to , split
    Ex: 123456 -> 123,456
    :param n:
    :return:
    """
    if n is None:
        return '0'
    n = str(n)
    if '.' in n:
        dollars, cents = n.split('.')
    else:
        dollars, cents = n, None

    r = []
    for i, c in enumerate(str(dollars)[::-1]):
        if i and (not (i % 3)):
            r.insert(0, ',')
        r.insert(0, c)
    out = ''.join(r)
    if cents:
        out += '.' + cents
    return out


def md5(content):
    """
    MD5 Hash
    :param content:
    :return:
    """
    content = content.encode('utf8')
    return hashlib.md5(content).hexdigest()


def path_to_short(path, max_length=36):
    """
    /impl/src/main/java/com/mogujie/service/mgs/digitalcert/utils/CertUtil.java
    /impl/src/.../utils/CertUtil.java
    :param path:
    :param max_length:
    :return:
    """
    if len(path) < max_length:
        return path
    paths = path.split('/')
    paths = filter(None, paths)
    paths = list(paths)
    tmp_path = ''
    for i in range(0, len(paths)):
        logger.debug((i, str(paths[i]), str(paths[len(paths) - i - 1])))
        tmp_path = tmp_path + str(paths[i]) + '/' + str(paths[len(paths) - i - 1])
        if len(tmp_path) > max_length:
            tmp_path = ''
            for j in range(0, i):
                tmp_path = tmp_path + '/' + str(paths[j])
            tmp_path += '/...'
            for k in range(i, 0, -1):
                tmp_path = tmp_path + '/' + str(paths[len(paths) - k])
            if tmp_path == '/...':
                return '.../{0}'.format(paths[len(paths) - 1])
            elif tmp_path[0] == '/':
                return tmp_path[1:]
            else:
                return tmp_path


def path_to_file(path):
    """
    Path to file
    /impl/src/main/java/com/mogujie/service/mgs/digitalcert/utils/CertUtil.java
    .../CertUtil.java
    :param path:
    :return:
    """
    paths = path.split('/')
    paths = list(filter(None, paths))
    length = len(paths)
    return '.../{0}'.format(paths[length - 1])


def percent(part, whole, need_per=True):
    """
    Percent
    :param part:
    :param whole:
    :param need_per:
    :return:
    """
    if need_per:
        per = '%'
    else:
        per = ''
    if part == 0 and whole == 0:
        return 0
    return '{0}{1}'.format(100 * float(part) / float(whole), per)


def timestamp():
    """Get timestamp"""
    return int(time.time())


def format_gmt(time_gmt, time_format=None):
    """
    Format GMT time
    Ex: Wed, 14 Sep 2016 17:57:41 GMT to 2016-09-14 17:57:41
    :param time_gmt:
    :param time_format:
    :return:
    """
    if time_format is None:
        time_format = '%Y-%m-%d %X'
    t = time.strptime(time_gmt, "%a, %d %b %Y %H:%M:%S GMT")
    return time.strftime(time_format, t)


def random_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


def is_list(value):
    """
    Returns True if the given value is a list-like instance

    >>> is_list([1, 2, 3])
    True
    >>> is_list(u'2')
    False
    """

    return isinstance(value, (list, tuple, set))


def get_unicode(value, encoding=None, none_to_null=False):
    """
    Return the unicode representation of the supplied value:

    >>> get_unicode(u'test')
    u'test'
    >>> get_unicode('test')
    u'test'
    >>> get_unicode(1)
    u'1'
    """

    if none_to_null and value is None:
        return None
    if str(type(value)) == "<class 'bytes'>":
        value = value.encode('utf8')
        return value
    elif str(type(value)) == "<type 'unicode'>":
        return value
    elif is_list(value):
        value = list(get_unicode(_, encoding, none_to_null) for _ in value)
        return value
    else:
        try:
            return value.encode('utf8')
        except UnicodeDecodeError:
            return value.encode('utf8', errors="ignore")


def get_safe_ex_string(ex, encoding=None):
    """
    Safe way how to get the proper exception represtation as a string
    (Note: errors to be avoided: 1) "%s" % Exception(u'\u0161') and 2) "%s" % str(Exception(u'\u0161'))

    >>> get_safe_ex_string(Exception('foobar'))
    u'foobar'
    """

    ret = ex

    if getattr(ex, "message", None):
        ret = ex.message
    elif getattr(ex, "msg", None):
        ret = ex.msg

    return get_unicode(ret or "", encoding=encoding).strip()


def class_to_path(target_projects, class_name):
    """
    转换Java class名为绝对路径，用于跨文件的检测
    :param target_projects: 项目根目录
    :param class_name: import类名
    :return:
    """
    class_path = ''

    if class_name and '.' in class_name:
        class_rpath = class_name.replace('.', '/') + '.java'  # 转换类名为相对路径
    else:
        class_rpath = ''
        logger.warning("[UNTIL] Class_name can't None, False or empty !")

    if target_projects:
        for root, dirs, files in os.walk(target_projects):
            for f in files:
                if f.endswith('.java'):
                    class_new_path = os.path.join(root, f)
                    if class_rpath in class_new_path:
                        class_path = class_new_path

        if class_path != '':
            logger.debug("[UNTIL] The class {c} path {p}".format(c=class_name, p=class_path))
    else:
        logger.warning("[UNTIL] Target_projects can't None, False or empty !")

    return class_path

