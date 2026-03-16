# -*- coding: utf-8 -*-

"""
    engine
    ~~~~~~

    Implements scan engine

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/WhaleShark-Team/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2018 Feei. All rights reserved
"""
import os
import re
import json
import traceback
import multiprocessing
from . import const
from .rule import Rule
from .log import logger
from .config import running_path
from .result import VulnerabilityResult
from .cast import CAST
from .parser import scan_parser


class Running:
    def __init__(self, sid):
        self.sid = sid

    def data(self, data=None):
        """
        存储分析结果
        """
        file_path = os.path.join(running_path, '{sid}_data'.format(sid=self.sid))
        data = json.dumps(data, sort_keys=True)
        with open(file_path, 'w+') as f:
            f.writelines(data)


def score2level(score):
    level_score = {
        'CRITICAL': [9, 10],
        'HIGH': [6, 7, 8],
        'MEDIUM': [3, 4, 5],
        'LOW': [1, 2]
    }
    score = int(score)
    level = None
    for l in level_score:
        if score in level_score[l]:
            level = l
    if level is None:
        return 'Unknown'
    else:
        if score < 10:
            score_full = '0{s}'.format(s=score)
        else:
            score_full = score
        return '{l}-{s}'.format(l=level[:1], s=score_full)


def scan_single(target_directory, single_rule, scan_file_list=None):
    try:
        return SingleRule(target_directory, single_rule, scan_file_list=scan_file_list).process()
    except Exception:
        raise


def scan(target_directory, s_sid=None, special_rules=None, scan_file_list=None):
    r = Rule()
    languages = r.languages
    rules = r.rules(special_rules)
    find_vulnerabilities = []

    # try:
    #     if special_rules is None or len(special_rules) == 0:
    #         cve_vuls = scan_cve(target_directory)
    #         find_vulnerabilities += cve_vuls
    #     else:
    #         for rule in rules:
    #             if rule.get('id').lower()[0:3] == '999':
    #                 cve_vuls = scan_cve(target_directory, 'CVI-{num}.xml'.format(num=rule.get('id')))
    #                 find_vulnerabilities += cve_vuls
    # except Exception:
    #     logger.warning('[SCAN] [CVE] CVE rule is None')

    def store(result):
        if result is not None and isinstance(result, list) is True:
            for res in result:
                if os.path.isdir(target_directory):
                    res.file_path = res.file_path.replace(target_directory, '').lstrip('/')
                else:
                    res.file_path = res.file_path.replace(os.path.dirname(target_directory), '').lstrip('/')

                find_vulnerabilities.append(res)
        else:
            logger.debug('[SCAN] [STORE] Not found vulnerabilities on this rule!')

    try:
        if len(rules) == 0:
            logger.critical('no rules!')
            return False
        logger.info('[PUSH] {rc} Rules'.format(rc=len(rules)))
        pool = multiprocessing.Pool()
        push_rules = []
        off_rules = 0
        for idx, single_rule in enumerate(rules):
            # 检查rules状态
            if single_rule['status'] is False:
                off_rules += 1
                logger.debug('[CVI-{cvi}] [STATUS] OFF, CONTINUE...'.format(cvi=single_rule['id']))
                continue
            # SR(Single Rule)
            logger.debug("""[PUSH] [CVI-{cvi}] {idx}.{name}({language})""".format(
                cvi=single_rule['id'],
                idx=idx,
                name=single_rule['name'],
                language=single_rule['language']
            ))
            if single_rule['language'] in languages:
                single_rule['extensions'] = languages[single_rule['language']]['extensions']
                push_rules.append(single_rule['id'])
                # 运行rules
                pool.apply_async(scan_single, args=(target_directory, single_rule, scan_file_list), callback=store)
            else:
                logger.critical('unset language, continue...')
                continue
        pool.close()
        pool.join()
    except Exception:
        raise

    vn = len(find_vulnerabilities)
    if vn == 0:
        logger.info('[SCAN] Not found vulnerability!')
    else:
        logger.info("[SCAN] Vulnerabilities ({vn})".format(vn=len(find_vulnerabilities)))

 
    # completed running data
    if s_sid is not None:
        Running(s_sid).data({
            'code': 1001,
            'msg': 'scan finished',
            'result': {
                'vulnerabilities': [x.__dict__ for x in find_vulnerabilities],
                'target_directory': target_directory,
            }
        })
    return True


class SingleRule(object):
    def __init__(self, target_directory, single_rule, scan_file_list=None):
        self.target_directory = target_directory
        self.sr = single_rule
        self.scan_file_list = scan_file_list if scan_file_list else []
        # Single Rule Vulnerabilities
        """
        [
            vr
        ]
        """
        self.rule_vulnerabilities = []

    def origin_results(self):
        logger.debug('[ENGINE] [ORIGIN] match-mode {m}'.format(m=self.sr['match-mode']))
        # 根据匹配模式构造正则表达式
        if self.sr['match-mode'] == const.mm_regex_only_match or self.sr['match-mode'] == const.mm_regex_param_controllable:
            match = self.sr['match']
        elif self.sr['match-mode'] == const.mm_function_param_controllable:
            # param controllable
            if '|' in self.sr['match']:
                match = const.fpc_multi.replace('[f]', self.sr['match'])
            else:
                match = const.fpc_single.replace('[f]', self.sr['match'])
        else:
            logger.warning('Exception match mode: {m}'.format(m=self.sr['match-mode']))
            return None

        # 编译正则表达式
        try:
            pattern = re.compile(match)
        except re.error as e:
            logger.critical('[CVI-{cvi}] [ORIGIN] 正则编译失败: {err}'.format(cvi=self.sr['id'], err=str(e)))
            return None

        # 获取当前规则的语言后缀列表
        extensions = self.sr.get('extensions', [])

        # 需要排除的目录
        explode_dirs = {'.svn', '.cvs', '.hg', '.git', '.bzr'}

        results = []

        # 遍历 scan_file_list 中的文件，逐行进行正则匹配
        for file_path in self.scan_file_list:
            # 构造完整文件路径
            if os.path.isabs(file_path):
                full_path = file_path
            else:
                full_path = os.path.join(self.target_directory, file_path)

            # 检查文件是否存在
            if not os.path.isfile(full_path):
                logger.debug('[ENGINE] [ORIGIN] 文件不存在，跳过: {f}'.format(f=full_path))
                continue

            # 检查文件后缀是否匹配当前规则的语言后缀
            if len(extensions) > 0:
                ext_match = False
                for ext in extensions:
                    if full_path.endswith(ext):
                        ext_match = True
                        break
                if not ext_match:
                    continue

            # 检查是否在排除目录中
            path_parts = full_path.replace('\\', '/').split('/')
            if any(part in explode_dirs for part in path_parts):
                continue

            # 逐行读取文件内容并进行正则匹配
            try:
                with open(full_path, 'r', errors='ignore') as f:
                    for line_number, line in enumerate(f, 1):
                        line = line.rstrip('\n').rstrip('\r')
                        if pattern.search(line):
                            # 保持与原 grep 输出一致的格式: 文件路径:行号:匹配内容
                            results.append('{fp}:{ln}:{code}'.format(
                                fp=full_path,
                                ln=line_number,
                                code=line
                            ))
            except Exception as e:
                logger.warning('[CVI-{cvi}] [ORIGIN] 读取文件异常 {f}: {err}'.format(
                    cvi=self.sr['id'], f=full_path, err=str(e)))
                continue

        return '\n'.join(results)

    def process(self):
        """
        Process Single Rule
        :return: SRV(Single Rule Vulnerabilities)
        """
        origin_results = self.origin_results()
        # exists result
        if origin_results == '' or origin_results is None:
            logger.debug('[CVI-{cvi}] [ORIGIN] NOT FOUND!'.format(cvi=self.sr['id']))
            return None

        origin_vulnerabilities = origin_results.strip().split("\n")
        for index, origin_vulnerability in enumerate(origin_vulnerabilities):
            origin_vulnerability = origin_vulnerability.strip()
            logger.debug('[CVI-{cvi}] [ORIGIN] {line}'.format(cvi=self.sr['id'], line=origin_vulnerability))
            if origin_vulnerability == '':
                logger.debug(' > continue...')
                continue
            vulnerability = self.parse_match(origin_vulnerability)
            if vulnerability is None:
                logger.debug('Not vulnerability, continue...')
                continue
            is_test = False
            try:
                is_vulnerability, reason = Core(self.target_directory, vulnerability, self.sr, 'project name', ['whitelist1', 'whitelist2'], test=is_test, index=index, scan_file_list=self.scan_file_list).scan()
                if is_vulnerability:
                    logger.debug('[CVI-{cvi}] [RET] Found {code}'.format(cvi=self.sr['id'], code=reason))
                    vulnerability.analysis = reason
                    match_result = re.findall(r"^(#|\/\*|\/\/)+", vulnerability.code_content)  # 判断漏洞代码是否在注释中
                    if len(match_result) > 0:
                        logger.debug('[CVI-{cvi} [RET] Found vul in annotation]')
                        vulnerability.code_content = vulnerability.code_content + vulnerability.analysis
                    self.rule_vulnerabilities.append(vulnerability)
                else:
                    logger.debug('Not vulnerability: {code}'.format(code=reason))
            except Exception:
                raise
        logger.debug('[CVI-{cvi}] {vn} Vulnerabilities: {count}'.format(cvi=self.sr['id'], vn=self.sr['name'], count=len(self.rule_vulnerabilities)))
        return self.rule_vulnerabilities

    def parse_match(self, single_match):
        mr = VulnerabilityResult()
        # grep result
        if ':' in single_match:
            #
            # Rules
            #
            # v.php:2:$password = "C787AFE9D9E86A6A6C78ACE99CA778EE";
            # v.php:2:$password 2017:01:01
            # v.exe Binary file
            try:
                if os.path.isdir(self.target_directory):
                    mr.line_number, mr.code_content = re.findall(r':(\d+):(.*)', single_match)[0]
                    mr.file_path = single_match.split(u':{n}:'.format(n=mr.line_number))[0]
                else:
                    mr.line_number, mr.code_content = re.findall(r'(\d+):(.*)', single_match)[0]
                    mr.file_path = self.target_directory
            except Exception:
                logger.warning('match line parse exception')
                mr.file_path = ''
                mr.code_content = ''
                mr.line_number = 0
        else:
            if 'Binary file' in single_match:
                return None
            else:
                # find result
                mr.file_path = single_match
                mr.code_content = ''
                mr.line_number = 0
        # vulnerability information
        mr.rule_name = self.sr['name']
        mr.id = self.sr['id']
        mr.language = self.sr['language']
        mr.solution = self.sr['solution']
        mr.level = self.sr['level']

        # committer
        # from .pickup import Git
        # c_ret, c_author, c_time = Git.committer(self.target_directory, mr.file_path, mr.line_number)
        # if c_ret:
        #     mr.commit_author = c_author
        #     mr.commit_time = c_time
        return mr


class Core(object):
    def __init__(self, target_directory, vulnerability_result, single_rule, project_name, white_list, test=False, index=None, scan_file_list=None):
        """
        Initialize
        :param: target_directory:
        :param: vulnerability_result:
        :param single_rule: rule info
        :param project_name: project name
        :param white_list: white-list
        :param test: is test
        :param index: vulnerability index
        :param scan_file_list: 扫描文件列表，只扫描在此列表中的文件
        """
        self.data = []

        self.target_directory = target_directory

        self.file_path = vulnerability_result.file_path.strip()
        self.line_number = vulnerability_result.line_number
        self.code_content = vulnerability_result.code_content.strip()

        self.rule_match = single_rule['match']
        self.rule_match_mode = single_rule['match-mode']
        self.rule_match2 = single_rule['match2']
        self.rule_match2_block = single_rule['match2-block']
        self.rule_repair = single_rule['repair']
        self.repair_block = single_rule['repair-block']
        self.cvi = single_rule['id']

        self.project_name = project_name
        self.white_list = white_list
        self.test = test

        self.status = None
        self.status_init = 0
        self.status_fixed = 2

        # const.py
        self.repair_code = None
        self.repair_code_init = 0
        self.repair_code_fixed = 1
        self.repair_code_not_exist_file = 4000
        self.repair_code_special_file = 4001
        self.repair_code_whitelist = 4002
        self.repair_code_test_file = 4003
        self.repair_code_annotation = 4004
        self.repair_code_modify = 4005
        self.repair_code_empty_code = 4006
        self.repair_code_const_file = 4007
        self.repair_code_third_party = 4008

        self.scan_file_list = scan_file_list if scan_file_list else []

        self.method = None
        logger.debug("""[CVI-{cvi}] [VERIFY-VULNERABILITY] ({index})
        > File: `{file}:{line}`
        > Code: `{code}`
        > Match2: `{m2}({m2b})`
        > Repair: `{r}({rb})`""".format(
            cvi=single_rule['id'],
            index=index,
            file=self.file_path.replace(self.target_directory, ''),
            line=self.line_number,
            code=self.code_content,
            m2=self.rule_match2,
            m2b=self.rule_match2_block,
            r=self.rule_repair,
            rb=self.repair_block))

    def is_white_list(self):
        """
        Is white-list file
        :return: boolean
        """
        return self.file_path.split(self.target_directory, 1)[1] in self.white_list

    def is_special_file(self):
        """
        Is special file
        :method: According to the file name to determine whether the special file
        :return: boolean
        """
        special_paths = [
            '/node_modules/',
            '/bower_components/',
            '.min.js',
            '.log',
            '.log.',
            'nohup.out',
        ]
        for path in special_paths:
            if path in self.file_path:
                return True
        return False

    def is_test_file(self):
        """
        Is test case file
        :method: file name
        :return: boolean
        """
        test_paths = [
            '/test/',
            '/tests/',
            '/unitTests/'
        ]
        for path in test_paths:
            if path in self.file_path:
                return True
        return False

    def is_match_only_rule(self):
        """
        Whether only match the rules, do not parameter controllable processing
        :method: It is determined by judging whether the left and right sides of the regex_location are brackets
        :return: boolean
        """
        if self.rule_match_mode == 'regex-only-match':
            return True
        else:
            return False

    def is_annotation(self):
        """
        Is annotation
        :method: Judgment by matching comment symbols (skipped when self.is_match_only_rule condition is met)
               - PHP:  `#` `//` `\*` `*`
                    //asdfasdf
                    \*asdfasdf
                    #asdfasdf
                    *asdfasdf
               - Java:
        :return: boolean
        """
        match_result = re.findall(r"^(#|\/\*|\/\/)+", self.code_content)
        # Skip detection only on match
        if self.is_match_only_rule():
            return False
        else:
            return len(match_result) > 0

    def is_can_parse(self):
        """
        Whether to parse the parameter is controllable operation
        :return:
        """
        for language in CAST.languages:
            if self.file_path[-len(language):].lower() == language:
                return True
        return False

    def scan(self):
        """
        Scan vulnerabilities
        :flow:
        - whitelist file
        - special file
        - test file
        - annotation
        - rule
        :return: is_vulnerability, code
        """
        self.method = 0
        if len(self.code_content) > 512:
            self.code_content = self.code_content[:500]
        self.status = self.status_init
        self.repair_code = self.repair_code_init

        # 扫描文件列表判断：如果指定了扫描文件列表，只扫描列表内的文件
        if self.file_path not in self.scan_file_list:
            return False, f"File {self.file_path} not in scan file list"

        if self.is_white_list():
            logger.debug("[RET] Whitelist")
            return False, 'Whitelists(白名单)'

        if self.is_special_file():
            logger.debug("[RET] Special File")
            return False, 'Special File(特殊文件)'

        if self.is_test_file():
            logger.debug("[CORE] Test File")

        if self.is_annotation():
            logger.debug("[RET] Annotation")
            return False, 'Annotation(注释)'

        if self.rule_match_mode == const.mm_regex_only_match:
            #
            # Regex-Only-Match
            # Match(regex) -> Repair -> Done
            #
            logger.debug("[CVI-{cvi}] [ONLY-MATCH]".format(cvi=self.cvi))
            if self.rule_match2 is not None:
                ast = CAST(self.rule_match, self.target_directory, self.file_path, self.line_number, self.code_content)
                is_match, data = ast.match(self.rule_match2, self.rule_match2_block)
                if is_match:
                    logger.debug('[CVI-{cvi}] [MATCH2] True'.format(cvi=self.cvi))
                else:
                    logger.debug('[CVI-{cvi}] [MATCH2] False'.format(cvi=self.cvi))
                    return False, 'REGEX-ONLY-MATCH+Not matched2(未匹配到二次规则)'

            if self.rule_repair is not None:
                logger.debug('[VERIFY-REPAIR]')
                ast = CAST(self.rule_match, self.target_directory, self.file_path, self.line_number, self.code_content)
                is_repair, data = ast.match(self.rule_repair, self.repair_block)
                if is_repair:
                    # fixed
                    logger.debug('[CVI-{cvi}] [RET] Vulnerability Fixed'.format(cvi=self.cvi))
                    return False, 'REGEX-ONLY-MATCH+Vulnerability-Fixed(漏洞已修复)'
                else:
                    logger.debug('[CVI-{cvi}] [REPAIR] [RET] Not fixed'.format(cvi=self.cvi))
                    return True, 'REGEX-ONLY-MATCH+NOT FIX(未修复)'

            else:
                match_result = re.findall(r"^(#|\/\*|\/\/)+", self.code_content)
                if len(match_result) > 0:
                    return True, 'REGEX-ONLY-MATCH(注释中存在漏洞，建议删除漏洞代码)'
                return True, 'REGEX-ONLY-MATCH(正则仅匹配+无修复规则)'
        else:
            #
            # Function-Param-Controllable
            # Match(function) -> Match2(regex) -> Param-Controllable -> Repair -> Done
            #

            #
            # Regex-Param-Controllable
            # Match(regex) -> Match2(regex) -> Param-Controllable -> Repair -> Done
            #
            logger.debug('[CVI-{cvi}] match-mode {mm}'.format(cvi=self.cvi, mm=self.rule_match_mode))
            if self.file_path[-3:].lower() == 'php':
                try:
                    ast = CAST(self.rule_match, self.target_directory, self.file_path, self.line_number, self.code_content)
                    rule_repair = []
                    if self.rule_match_mode == const.mm_function_param_controllable:
                        rule_match = self.rule_match.strip('()').split('|')  # 漏洞规则整理为列表
                        if self.rule_repair is not None:
                            rule_repair = self.rule_repair.strip('()').split('|')  # 修复规则整理为列表
                        logger.debug('[RULE_MATCH] {r}'.format(r=rule_match))
                        try:
                            with open(self.file_path, 'r') as fi:
                                code_contents = fi.read()
                                result = scan_parser(code_contents, rule_match, self.line_number, rule_repair)
                                logger.debug('[AST] [RET] {c}'.format(c=result))
                                if len(result) > 0:
                                    if result[0]['code'] == 1:  # 函数参数可控
                                        return True, 'FUNCTION-PARAM-CONTROLLABLE(函数入参可控)'

                                    if result[0]['code'] == 2:  # 函数为敏感函数
                                        return False, 'FUNCTION-PARAM-CONTROLLABLE(函数入参来自所在函数)'

                                    if result[0]['code'] == 0:  # 漏洞修复
                                        return False, 'FUNCTION-PARAM-CONTROLLABLE+Vulnerability-Fixed(漏洞已修复)'

                                    if result[0]['code'] == -1:  # 函数参数不可控
                                        return False, 'FUNCTION-PARAM-CONTROLLABLE(入参不可控)'

                                    logger.debug('[AST] [CODE] {code}'.format(code=result[0]['code']))
                                else:
                                    logger.debug('[AST] Parser failed / vulnerability parameter is not controllable {r}'.format(r=result))
                        except Exception as e:
                            logger.warning(traceback.format_exc())
                            raise

                    # Match2
                    if self.rule_match2 is not None:
                        is_match, data = ast.match(self.rule_match2, self.rule_match2_block)
                        if is_match:
                            logger.debug('[CVI-{cvi}] [MATCH2] True'.format(cvi=self.cvi))
                        else:
                            logger.debug('[CVI-{cvi}] [MATCH2] False'.format(cvi=self.cvi))
                            return False, 'FPC+NOT-MATCH2(函数入参可控+二次未匹配)'

                    # Param-Controllable
                    param_is_controllable, data = ast.is_controllable_param()
                    if param_is_controllable:
                        logger.debug('[CVI-{cvi}] [PARAM-CONTROLLABLE] Param is controllable'.format(cvi=self.cvi))
                        # Repair
                        is_repair, data = ast.match(self.rule_repair, self.repair_block)
                        if is_repair:
                            # fixed
                            logger.debug('[CVI-{cvi}] [REPAIR] Vulnerability Fixed'.format(cvi=self.cvi))
                            return False, 'Vulnerability-Fixed(漏洞已修复)'
                        else:
                            logger.debug('[CVI-{cvi}] [REPAIR] [RET] Not fixed'.format(cvi=self.cvi))
                            return True, 'MATCH+REPAIR(匹配+未修复)'
                    else:
                        logger.debug('[CVI-{cvi}] [PARAM-CONTROLLABLE] Param Not Controllable'.format(cvi=self.cvi))
                        return False, 'Param-Not-Controllable(参数不可控)'
                except Exception as e:
                    logger.debug(traceback.format_exc())
                    return False, 'Exception'
