"""Execute verified team functions without running their interactive entrypoints.

The vendored files are byte-identical ZIP members. Only dependencies, I/O and
configuration are supplied here; selected function bodies are compiled unchanged.
This is an integration boundary for trusted bundled code, not a code sandbox.
"""
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import time
from types import SimpleNamespace
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit, parse_qs, unquote_plus

VENDOR = Path(__file__).resolve().parents[1] / 'vendor' / 'log_team_optimization'


def source_namespace(filename, functions, constants=(), **dependencies):
    relative = 'log_team/pipeline/tools/' + filename
    manifest = json.loads((VENDOR / 'manifest.json').read_text(encoding='utf-8'))
    path = VENDOR / relative
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest['files'][relative]:
        raise ValueError('로그팀 원본 파일 무결성 확인 실패: ' + filename)
    tree = ast.parse(raw, filename=str(path))
    nodes = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in functions:
            nodes.append(node)
        elif isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in constants for t in node.targets):
            nodes.append(node)
    found = {n.name for n in nodes if isinstance(n, ast.FunctionDef)}
    if set(functions) != found:
        raise ValueError('로그팀 함수 구성을 확인하세요: ' + filename)
    namespace = {'__file__': str(path), 'print': lambda *a, **kw: None,
                 'Path': Path, 're': re, 'json': json, 'os': os, 'time': time,
                 'datetime': datetime, 'Any': Any, 'urlsplit': urlsplit,
                 'parse_qs': parse_qs, 'unquote_plus': unquote_plus, **dependencies}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), namespace)
    return namespace


def ml_functions():
    import pandas as pd
    from pandas.errors import EmptyDataError
    return source_namespace('final_test.py', ['load_data', 'rename_columns', 'predict'],
                            ['MAPPING'], pd=pd, EmptyDataError=EmptyDataError)


def convert_pcap(source, destination):
    from cicflowmeter.sniffer import create_sniffer
    import scapy.sendrecv as sr
    from scapy.all import PcapReader
    from external.config import MAX_RECORDS, MAX_FILE_BYTES
    if Path(source).stat().st_size > MAX_FILE_BYTES:
        raise ValueError('PCAP 크기 제한을 초과했습니다.')
    with PcapReader(str(source)) as packets:
        for index, _ in enumerate(packets):
            if index >= MAX_RECORDS:
                raise ValueError('패킷 제한(20,000개)을 초과했습니다.')
    # Match the original final_test.py import-time hook inside this child only.
    previous = sr.tcpdump
    sr.tcpdump = lambda fname, *args, **kwargs: open(fname, 'rb')
    try:
        functions = source_namespace('final_test.py', ['pcap_to_csv'], create_sniffer=create_sniffer)
        functions['pcap_to_csv'](source, destination)
    finally:
        sr.tcpdump = previous


def original_capture_command(executable, interface, duration, destination):
    """Use the team's finite capture entrypoint to construct its command.

    Execution is handed back to Scanner for cancellation/exit-code supervision.
    BPF and capture limits are added by collection.capture_command.
    """
    commands = []
    def run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0)
    namespace = source_namespace('get_PacketLog.py', ['start_pcap_dumper_once'],
        DEFAULT_TIME=duration, DUMPCAP_PATH=executable,
        setup_directory=lambda: str(Path(destination).parent),
        setup_fileName=lambda: str(destination), get_auto_interface=lambda _: interface,
        subprocess=SimpleNamespace(run=run, CalledProcessError=subprocess.CalledProcessError))
    namespace['start_pcap_dumper_once'](duration)
    if len(commands) != 1:
        raise ValueError('원본 패킷 수집 명령을 생성하지 못했습니다.')
    return commands[0]


class MemoryOutput(io.StringIO):
    def __init__(self, name, saved):
        super().__init__()
        self.name, self.saved = str(name), saved

    def close(self):
        if not self.closed:
            self.saved[self.name] = self.getvalue()
        super().close()


def regex_results(records):
    saved = {}
    def memory_open(name, mode='r', **kwargs):
        if 'w' in mode:
            return MemoryOutput(name, saved)
        return io.StringIO('\n'.join(json.dumps(row, ensure_ascii=False) for row in records))
    namespace = source_namespace('regex_filter.py', ['load_logs', 'filter_logs'],
                                 ['patterns'], open=memory_open)
    result = namespace['filter_logs']('input.json', 'output.json')
    return json.loads(saved[result]) if result else []


def parse_burp(text):
    """Replay a finite snapshot through the team's unchanged live parser."""
    from external.config import MAX_RECORDS
    saved, records = {}, []
    class Snapshot(io.StringIO):
        def seek(self, offset, whence=0):
            return super().seek(0 if whence == 2 else offset, 0 if whence == 2 else whence)
        def readline(self, *args):
            line = super().readline(*args)
            if not line:
                raise KeyboardInterrupt
            return line
    def memory_open(name, mode='r', **kwargs):
        return MemoryOutput(name, saved) if 'w' in mode else Snapshot(text.rstrip() + '\n\n==========\n')
    def put(name):
        if len(records) > MAX_RECORDS:
            raise KeyboardInterrupt
        row = json.loads(saved.pop(str(name)))
        row['timestamp_basis'] = 'collection_time'
        records.append(row)
    namespace = source_namespace('parser.py',
        ['is_static_file', 'is_separator', 'mask_cookie', 'build_log', 'get_WebLog_pipeline'],
        ['REQUEST_RE', 'RESPONSE_RE', 'STATIC_EXTENSIONS'], LOG_FILE='snapshot.log',
        open=memory_open, os=SimpleNamespace(path=os.path, makedirs=lambda *a, **kw: None))
    namespace['get_WebLog_pipeline'](SimpleNamespace(put=put), 'snapshot.log')
    if len(records) > MAX_RECORDS:
        raise ValueError('웹 로그 항목 제한(20,000개)에 도달했습니다.')
    return records


def export_network(result, model, source_file):
    """Original aggregation/exporter, with file writes routed into memory."""
    import pandas as pd
    from zoneinfo import ZoneInfo
    saved = {}
    class MemoryPath:
        def __init__(self, value):
            self.value = Path(str(value))
        def __str__(self):
            return str(self.value)
        @property
        def name(self):
            return self.value.name
        @property
        def stem(self):
            return self.value.stem
        def __truediv__(self, value):
            return MemoryPath(self.value / value)
        def mkdir(self, **kwargs):
            pass
        def resolve(self):
            return self
        def open(self, *args, **kwargs):
            return MemoryOutput(self, saved)
    class Clock(datetime):
        def astimezone(self, tz=None):
            return super().astimezone(tz or ZoneInfo(os.environ.get('EXTERNAL_TIMEZONE', 'Asia/Seoul')))
    namespace = source_namespace('result_exporter.py', ['save_prediction_json'],
        Path=MemoryPath, pd=pd, OUTPUT_DIR=MemoryPath('memory'), datetime=Clock)
    path = namespace['save_prediction_json'](result, model, source_file, 'prediction.csv', 'memory')
    value = json.loads(saved[str(path)])
    value.pop('prediction_csv', None)
    return value
