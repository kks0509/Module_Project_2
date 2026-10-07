"""Branded entry point: python -m rookies_scanner."""
from pathlib import Path
import subprocess
import sys


def main():
    app = Path(__file__).resolve().parent / 'app.py'
    return subprocess.call([sys.executable, '-m', 'streamlit', 'run', str(app),
                            '--server.address=127.0.0.1', '--server.port=8501', *sys.argv[1:]])

if __name__ == '__main__':
    sys.exit(main())
