# -*- coding: utf-8 -*-

"""
Cobra Config
"""
import os

project_directory = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))

code_path = os.path.join(project_directory, "logs")
if os.path.isdir(code_path) is not True:
    os.mkdir(code_path)

running_path = os.path.join(code_path, 'running')
if os.path.isdir(running_path) is not True:
    os.mkdir(running_path)

cobra_main = os.path.join(project_directory, 'cobra.py')
tests_path = os.path.join(project_directory, 'tests')
examples_path = os.path.join(tests_path, 'examples')
rules_path = os.path.join(project_directory, 'rules')
config_path = os.path.join(project_directory, 'config')
rule_path = os.path.join(project_directory, 'rule.cobra')


class Vulnerabilities(object):
    def __init__(self, key):
        self.key = key

    def status_description(self):
        status = {
            0: 'Not fixed',
            1: 'Not fixed(Push third-party)',
            2: 'Fixed'
        }
        if self.key in status:
            return status[self.key]
        else:
            return False

    def repair_description(self):
        repair = {
            0: 'Initialize',
            1: 'Fixed',
            4000: 'File not exist',
            4001: 'Special file',
            4002: 'Whitelist',
            4003: 'Test file',
            4004: 'Annotation',
            4005: 'Modify code',
            4006: 'Empty code',
            4007: 'Const file',
            4008: 'Third-party'
        }
        if self.key in repair:
            return repair[self.key]
        else:
            return False

    def level_description(self):
        level = {
            0: 'Undefined',
            1: 'Low',
            2: 'Medium',
            3: 'High',
        }
        if self.key in level:
            return level[self.key]
        else:
            return False
