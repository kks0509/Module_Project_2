"""ZeroTier-first capture discovery; Docker bridge is a secondary observation point."""
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import subprocess

NETWORK_NAME = 'lms-security-lab_lms-network'
CONTAINER_NAME = 'lms-web'
CONTAINER_FORMAT = '{"running": {{json .State.Running}}, "networks": {{json .NetworkSettings.Networks}}}'


@dataclass(frozen=True)
class CaptureDiscovery:
    ok: bool = False
    network_name: str = NETWORK_NAME
    container_name: str = CONTAINER_NAME
    network_id: str = ''
    interface: str = ''
    container_ip: str = ''
    port: int = 5000
    reason: str = ''
    selection: str = 'docker_auto'
    fallback_reason: str = ''

    @property
    def capture_filter(self):
        if not self.ok:
            return ''
        if self.selection == 'zerotier_auto':
            return f'tcp port {self.port}'
        return f'host {self.container_ip} and tcp port {self.port}'

    def metadata(self):
        return {**asdict(self), 'capture_filter': self.capture_filter,
                'checked_at': datetime.now(timezone.utc).isoformat()}


def linux_interface_exists(interface):
    return bool(re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', interface)) and (Path('/sys/class/net') / interface).is_dir()


def zerotier_interfaces():
    """Enumerate current Linux ZeroTier interface names; no cached literal NIC name."""
    try:
        return sorted(entry.name for entry in Path('/sys/class/net').iterdir()
                      if re.fullmatch(r'zt[A-Za-z0-9]{1,13}', entry.name) and entry.is_dir())
    except OSError:
        return []


def detect_zerotier_capture():
    values = {'selection': 'zerotier_auto', 'network_name': '', 'container_name': ''}
    try:
        if platform.system() != 'Linux':
            raise ValueError('ZeroTier 자동 감지는 앱이 실행되는 Linux 호스트에서 사용할 수 있습니다.')
        port = int(os.environ.get('EXTERNAL_ZEROTIER_PORT', '5000'))
        if not 1 <= port <= 65535:
            raise ValueError('ZeroTier 수집 포트는 1~65535여야 합니다.')
        values['port'] = port
        candidates = zerotier_interfaces()
        preferred = os.environ.get('EXTERNAL_ZEROTIER_INTERFACE', '').strip()
        if preferred:
            if preferred not in candidates:
                raise ValueError('설정한 ZeroTier 인터페이스가 현재 Linux 호스트에 존재하지 않습니다.')
            interface = preferred
        elif len(candidates) == 1:
            interface = candidates[0]
        elif len(candidates) > 1:
            raise ValueError('ZeroTier 인터페이스가 여러 개입니다. 서버 EXTERNAL_ZEROTIER_INTERFACE로 선택하세요.')
        else:
            raise ValueError('현재 Linux 호스트에서 ZeroTier 인터페이스를 찾지 못했습니다.')
        if not linux_interface_exists(interface):
            raise ValueError('ZeroTier 인터페이스가 변경되었습니다. 다시 시작하세요.')
        return CaptureDiscovery(ok=True, interface=interface, **values)
    except ValueError as exc:
        return CaptureDiscovery(reason=str(exc)[:400], **values)


def inspect_json(command, description):
    try:
        result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8',
                                errors='replace', timeout=3, check=False, shell=False)
    except FileNotFoundError:
        raise ValueError('Docker 명령을 찾지 못했습니다. 앱 실행 서버의 Docker 설치를 확인하세요.') from None
    except subprocess.TimeoutExpired:
        raise ValueError('Docker 조회 시간이 초과되었습니다. Docker 서비스 상태를 확인하세요.') from None
    except OSError:
        raise ValueError('Docker 조회를 실행하지 못했습니다. 실행 권한을 확인하세요.') from None
    if result.returncode != 0:
        # Do not expose command stderr or container configuration to the browser.
        raise ValueError(description + ' 조회 실패: 이름·Docker 서비스·조회 권한을 확인하세요.')
    if len(result.stdout) > 1024 * 1024:
        raise ValueError('Docker 조회 응답 크기가 너무 큽니다.')
    try:
        return json.loads(result.stdout)
    except (ValueError, TypeError):
        raise ValueError('Docker 조회 응답 형식을 확인할 수 없습니다.') from None


def detect_docker_capture():
    network_name = os.environ.get('EXTERNAL_DOCKER_NETWORK', NETWORK_NAME).strip() or NETWORK_NAME
    container_name = os.environ.get('EXTERNAL_LMS_CONTAINER', CONTAINER_NAME).strip() or CONTAINER_NAME
    values = {'network_name': network_name, 'container_name': container_name}
    try:
        if platform.system() != 'Linux':
            raise ValueError('Docker bridge 자동 감지는 LMS가 실행되는 Linux 호스트에서 사용할 수 있습니다.')
        if not all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', n) for n in (network_name, container_name)):
            raise ValueError('서버 설정의 Docker 네트워크·컨테이너 이름을 확인하세요.')
        port = int(os.environ.get('EXTERNAL_LMS_PORT', '5000'))
        if not 1 <= port <= 65535:
            raise ValueError('LMS 컨테이너 포트는 1~65535여야 합니다.')
        values['port'] = port
        networks = inspect_json(['docker', 'network', 'inspect', network_name], 'LMS Docker Network')
        if not isinstance(networks, list) or len(networks) != 1 or not isinstance(networks[0], dict):
            raise ValueError('Docker 네트워크 응답 형식이 올바르지 않습니다.')
        network = networks[0]
        if network.get('Name') != network_name or network.get('Driver') != 'bridge':
            raise ValueError('지정한 LMS 네트워크가 Linux bridge 네트워크가 아닙니다.')
        identity = network.get('Id', '')
        if not isinstance(identity, str) or not re.fullmatch(r'[0-9a-f]{64}', identity):
            raise ValueError('Docker Network ID를 확인할 수 없습니다.')
        options = network.get('Options') or {}
        if not isinstance(options, dict):
            raise ValueError('Docker bridge 설정 형식이 올바르지 않습니다.')
        # Docker's explicit bridge-name option overrides the generated default.
        interface = options.get('com.docker.network.bridge.name') or 'br-' + identity[:12]
        if not isinstance(interface, str) or not linux_interface_exists(interface):
            raise ValueError('LMS Docker bridge 인터페이스가 Linux 호스트에 존재하지 않습니다.')
        values.update(network_id=identity, interface=interface)
        container = inspect_json(['docker', 'container', 'inspect', '--format', CONTAINER_FORMAT, container_name],
                                 'LMS 웹 컨테이너')
        if not isinstance(container, dict) or container.get('running') is not True:
            raise ValueError('LMS 웹 컨테이너가 실행 중인지 확인하세요.')
        attachments = container.get('networks')
        endpoint = attachments.get(network_name) if isinstance(attachments, dict) else None
        if not isinstance(endpoint, dict) or endpoint.get('NetworkID') != identity:
            raise ValueError('LMS 웹 컨테이너의 네트워크가 변경되었습니다. Docker 구성을 확인하고 다시 시도하세요.')
        address = ipaddress.ip_address(endpoint.get('IPAddress', ''))
        private = (ipaddress.ip_network('10.0.0.0/8'), ipaddress.ip_network('172.16.0.0/12'),
                   ipaddress.ip_network('192.168.0.0/16'))
        if address.version != 4 or not any(address in net for net in private):
            raise ValueError('LMS 웹 컨테이너의 사설 IPv4 주소를 확인할 수 없습니다.')
        values['container_ip'] = str(address)
        return CaptureDiscovery(ok=True, **values)
    except (ValueError, TypeError) as exc:
        # Unexpected/empty IP values should be as actionable as Docker failures.
        reason = str(exc) if type(exc) is ValueError else 'Docker 네트워크·컨테이너 응답을 확인하세요.'
        return CaptureDiscovery(reason=reason[:400], **values)


def detect_lms_capture():
    """Prefer the external ZeroTier segment; never arbitrarily pick among multiple NICs."""
    from dataclasses import replace
    zerotier = detect_zerotier_capture()
    if zerotier.ok:
        return zerotier
    docker = detect_docker_capture()
    if docker.ok:
        return replace(docker, fallback_reason=zerotier.reason)
    return replace(docker, reason=(zerotier.reason + ' ' + docker.reason)[:800],
                   fallback_reason=zerotier.reason)


def prepare_capture(config):
    """Validate a manual choice; discover only when explicitly requested by config."""
    if config.mode != 'live' or not config.network:
        return
    if not config.auto_capture:
        from urllib.parse import urlsplit
        manual = config.interface.strip()
        if not manual:
            raise ValueError('수집 인터페이스 이름을 직접 입력하세요.')
        if platform.system() == 'Linux' and not linux_interface_exists(manual):
            raise ValueError('입력한 수집 인터페이스가 현재 Linux 호스트에 존재하지 않습니다.')
        target = urlsplit(config.target)
        port = target.port or (443 if target.scheme == 'https' else 80)
        config.interface, config.capture_host, config.capture_port = manual, '', port
        config.capture_port_only = True
        config.capture_info = {'selection': 'manual', 'interface': manual,
                               'capture_filter': f'tcp port {port}',
                               'checked_at': datetime.now(timezone.utc).isoformat()}
        return
    detected = detect_lms_capture()
    if detected.ok:
        config.interface = detected.interface
        config.capture_host, config.capture_port = detected.container_ip, detected.port
        config.capture_port_only = detected.selection == 'zerotier_auto'
        config.capture_info = detected.metadata()
        return
    manual = config.fallback_interface.strip()
    if not manual:
        raise ValueError('ZeroTier / LMS Docker Network 인터페이스를 자동으로 찾지 못했습니다. ' + detected.reason +
                         ' 수집 인터페이스 직접 입력 후 다시 시작하세요.')
    if platform.system() == 'Linux' and not linux_interface_exists(manual):
        raise ValueError('수동 수집 인터페이스가 현재 Linux 호스트에 존재하지 않습니다.')
    config.interface, config.capture_host, config.capture_port = manual, '', 0
    config.capture_port_only = False
    config.capture_info = {'selection': 'manual_fallback', 'interface': manual,
                           'auto_detection_reason': detected.reason,
                           'checked_at': datetime.now(timezone.utc).isoformat()}
