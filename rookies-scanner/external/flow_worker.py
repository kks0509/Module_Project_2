"""Offline flow conversion in a cancellable subprocess using team CICFlowMeter."""
import sys
from external.config import MAX_RECORDS


def convert(source, destination):
    from external.team_adapter import convert_pcap
    convert_pcap(source, destination)


if __name__ == '__main__':
    try:
        convert(sys.argv[1], sys.argv[2])
    except Exception:
        # The parent reports a safe actionable error; no packet or path dump.
        sys.exit(2)
