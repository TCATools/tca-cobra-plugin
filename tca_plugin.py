# -*- encoding: utf-8 -*-
'''
Tca Cobra Plugin
'''
import os
import json
import subprocess

PWD = os.getcwd()
WOORK_DIR = os.environ.get("RESULT_DIR")
SOURCE_DIR = os.environ.get("SOURCE_DIR")

def decode_str(text) -> str:
    try:
        return text.decode(encoding='UTF-8')
    except UnicodeDecodeError:
        return text.decode(encoding="gbk", errors="surrogateescape")

def get_task_params() -> dict:
    """
    获取需要任务参数
    :return:
    """
    task_request_file = os.environ["TASK_REQUEST"]
    with open(task_request_file, "r") as rf:
        task_request = json.load(rf)
    task_params = task_request["task_params"]
    return task_params

class Cobra():

    def __init__(self, params):
        self.params = params
        self.tool = self._get_tool()

    def _get_tool(self) -> str:
        return os.path.join(PWD, "cobra.py")

    def analyze(self) -> list:
        print("当前使用的工具：" + self.tool)
        issues = []
        incr_scan = self.params["incr_scan"]
        relpos = len(SOURCE_DIR) + 1
        issues_file = os.path.join(WOORK_DIR, "cobra-result.json")
        scan_cmd = ["python3", "cobra.py", "-f", "json", "-o", issues_file, "-t", SOURCE_DIR]
        # rules去重
        rule_list = params["rule_list"]
        rule_names = set()
        rules = []
        for r in rule_list:
            if r["name"] not in rule_names:
                rule_names.add(r["name"])
                rules.append(r["name"])
        if rules:
            scan_cmd.extend(["-r", ",".join(rules)])
        if incr_scan:
            toscan = []
            with open(os.getenv("SCAN_FILES"), "r") as fr:
                task_file = json.load(fr)
            for file in task_file:
                if os.path.isfile(file):
                    toscan.append(file)
            if not toscan:
                return issues
            files_path = os.path.join(WOORK_DIR, "paths.txt")
            with open(files_path, "w", encoding="UTF-8") as f:
                f.write("\n".join(toscan))
            scan_cmd.extend(["--scan-list", files_path])
        print(scan_cmd)
        try:
            sp = subprocess.Popen(scan_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, stderr = sp.communicate(timeout=int(os.environ.get("TCA_TASK_TIMEOUT", "600")))
            if output:
                output_str = decode_str(output)
                for line in output_str.splitlines():
                    if line.strip():
                        print(line)
            if stderr:
                stderr_str = decode_str(stderr)
                print(stderr_str)
        except Exception as err:
            print(f"分析过程异常: {err}")
            return issues
        # 分析异常时可能生成空文件导致读取异常
        try:
            with open(issues_file, "r", encoding="utf-8") as fr:
                datas = json.load(fp=fr)
        except Exception as err:
            print(f"解析结果异常: {err}")
            return issues

        column = 0
        for (_, value) in datas.items():
            vulns = value["vulnerabilities"]
            for vuln in vulns:
                path = os.path.join(SOURCE_DIR, vuln["file_path"])
                line = int(vuln["line_number"])
                # rule = vuln['rule_name']
                rule = "CVI-" + vuln["id"]
                if rule.startswith("CVI-999"):
                    rule = "CVI-999XXX"

                msg = vuln["solution"] + "\n" + vuln["analysis"]
                issues.append({"path": path, "rule": rule, "msg": msg, "line": line, "column": column})
        return issues


if __name__ == "__main__":
    params = get_task_params()
    tool = Cobra(params)
    result_file = os.path.join(WOORK_DIR, "result.json")
    issues = tool.analyze()
    with open(result_file, "w") as fw:
        json.dump(issues, fw, indent=2)