"""Installation checks only. Does not contact a scan target."""
import argparse
import importlib.util
import sys


def main():
    parser = argparse.ArgumentParser(description='ROOKIES Scanner 실행 환경 확인')
    parser.add_argument('--gui', action='store_true', help='실제 Tk 창 생성 가능 여부 확인')
    args = parser.parse_args()
    failures = []
    if sys.version_info < (3, 10):
        failures.append('Python 3.10 이상이 필요합니다.')
    required = [('streamlit', '가상환경 Python으로 pip install -r requirements.txt'),
                         ('requests', '가상환경 Python으로 pip install -r requirements.txt'),
                         ('tzdata', '가상환경 Python으로 pip install -r requirements.txt'),
                         ('openai', '가상환경 Python으로 pip install -r requirements.txt'),
                         ('dotenv', '가상환경 Python으로 pip install -r requirements.txt')]
    if args.gui:
        required.append(('tkinter', 'sudo apt-get install python3-tk'))
    for module, hint in required:
        if importlib.util.find_spec(module) is None:
            failures.append(f'{module} 없음: {hint}')
    if args.gui and not failures:
        import tkinter as tk
        try:
            root = tk.Tk()
            root.withdraw()
            root.update_idletasks()
            root.destroy()
        except tk.TclError as exc:
            failures.append('GUI 연결 실패: Ubuntu 데스크톱에서 터미널을 열어 실행하세요. '
                            f'SSH/서버 환경에서는 그래픽 세션이 필요합니다. ({exc})')
    if failures:
        print('\n'.join(failures), file=sys.stderr)
        return 1
    print(f'실행 환경 확인 완료 · Python {sys.version.split()[0]}' + (' · GUI 사용 가능' if args.gui else ''))
    return 0


if __name__ == '__main__':
    sys.exit(main())
