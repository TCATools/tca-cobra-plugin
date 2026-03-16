import sys
import platform

__title__ = 'cobra'
__description__ = 'Code Security Audit'
__url__ = 'https://github.com/FeeiCN/Cobra'
__python_version__ = sys.version.split()[0]
__platform__ = platform.platform()
__version__ = '3.0.0'
__author__ = 'Feei'
__author_email__ = 'feei@feei.cn'
__license__ = 'MIT License'
__copyright__ = 'Copyright (c) 2018 Feei. All rights reserved'
__introduction__ = """
    ,---.     |
    |    ,---.|---.,---.,---.
    |    |   ||   ||    ,---|
    `---``---``---``    `---^ v{version}

Cobra is a static code analysis system that automates the detecting vulnerabilities and security issue.""".format(version=__version__)
__epilog__ = """Usage:
  python {m} -t {td}
  python {m} -t {td} -r cvi-190001,cvi-190002
  python {m} -t {td} -f json -o /tmp/report.json 
""".format(m='cobra.py', td='tests/vulnerabilities', tg='https://github.com/ethicalhack3r/DVWA')

