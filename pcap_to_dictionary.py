"""把 pcap 文件按 UCSB IP 整理成 dictionary。

依赖安装：
    pip install scapy

返回格式示例：
    {
        "128.111.10.20": ["flow_001.pcap", "flow_002.pcap"],
        "169.231.4.8": ["flow_003.pcap"]
    }
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Iterable

try:
    from scapy.all import IP, PcapReader
except ImportError as exc:
    raise SystemExit(
        "缺少 Scapy。请先运行：pip install scapy"
    ) from exc


# UCSB 的两个 IPv4 网段。
DEFAULT_UCSB_NETWORKS = ("128.111.0.0/16", "169.231.0.0/16")
PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap"}


def _parse_networks(networks: Iterable[str]) -> list[ipaddress.IPv4Network]:
    """把字符串网段转换成可用于 IP 判断的对象。"""
    parsed_networks: list[ipaddress.IPv4Network] = []
    for network in networks:
        parsed = ipaddress.ip_network(network, strict=False)
        if not isinstance(parsed, ipaddress.IPv4Network):
            raise ValueError(f"目前只支持 IPv4 网段：{network}")
        parsed_networks.append(parsed)
    return parsed_networks


def _is_ucsb_ip(
    ip_text: str, ucsb_networks: list[ipaddress.IPv4Network]
) -> bool:
    """检测一个 IPv4 地址是否属于任意 UCSB 网段。"""
    try:
        address = ipaddress.ip_address(ip_text)
    except ValueError:
        return False

    for network in ucsb_networks:
        if address in network:
            return True
    return False


def find_ucsb_ip(
    pcap_path: str | Path,
    ucsb_networks: Iterable[str] = DEFAULT_UCSB_NETWORKS,
) -> str | None:
    """用 Scapy 遍历 pcap，返回第一个出现在 srcIP 或 dstIP 的 UCSB IP。

    每个拆分后的 pcap 预期代表一个 flow，所以找到第一个带 UCSB 地址的
    IPv4 数据包后即可确定该文件的 UCSB 端点。
    """
    parsed_networks = _parse_networks(ucsb_networks)

    with PcapReader(str(pcap_path)) as packets:
        for packet in packets:
            if IP not in packet:
                continue

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # src 和 dst 都属于 UCSB 时，按要求优先选择 srcIP。
            if _is_ucsb_ip(src_ip, parsed_networks):
                return src_ip
            if _is_ucsb_ip(dst_ip, parsed_networks):
                return dst_ip

    return None


def _add_pcap_to_dictionary(
    result: dict[str, list[str]],
    pcap_path: Path,
    file_name: str,
    ucsb_networks: Iterable[str],
) -> None:
    """检查一个 pcap，并把文件名加入对应 UCSB IP 的列表。"""
    try:
        ucsb_ip = find_ucsb_ip(pcap_path, ucsb_networks)
    except Exception as exc:  # 坏文件不应中断整个目录的处理。
        print(f"跳过无法读取的文件 {file_name}: {exc}", file=sys.stderr)
        return

    # 没有 UCSB srcIP/dstIP 的文件不放入结果。
    if ucsb_ip is None:
        return

    # 已存在表示它与先前文件有相同的 UCSB flow 端点，追加文件名；
    # 不存在则先在 dictionary 中创建这个 key。
    if ucsb_ip not in result:
        result[ucsb_ip] = []

    # 避免同一个文件名被重复加入列表。
    if file_name not in result[ucsb_ip]:
        result[ucsb_ip].append(file_name)


def pcap_to_dictionary(
    source: str | Path,
    ucsb_networks: Iterable[str] = DEFAULT_UCSB_NETWORKS,
) -> dict[str, list[str]]:
    """把一个 pcap、pcap 目录或包含 pcap 的 zip 转换成 dictionary。

    Args:
        source: 单个 pcap、pcap 所在目录，或 zip 压缩包路径。
        ucsb_networks: UCSB IPv4 网段，默认包括 128.111/16 和 169.231/16。

    Returns:
        key 是 UCSB IP，value 是属于该 UCSB IP 的 pcap 文件名列表。
    """
    source_path = Path(source).expanduser().resolve()
    networks = tuple(ucsb_networks)
    # 提前验证输入网段，避免遍历到中途才报错。
    _parse_networks(networks)

    if not source_path.exists():
        raise FileNotFoundError(f"找不到输入路径：{source_path}")

    result: dict[str, list[str]] = {}

    if source_path.is_dir():
        # rglob 可以处理目录内的多层子目录。
        for pcap_path in sorted(source_path.rglob("*")):
            if pcap_path.is_file() and pcap_path.suffix.lower() in PCAP_SUFFIXES:
                relative_name = pcap_path.relative_to(source_path).as_posix()
                _add_pcap_to_dictionary(
                    result, pcap_path, relative_name, networks
                )
        return result

    if source_path.suffix.lower() == ".zip":
        # 每次只解压并处理一个 pcap，避免一次性占用大量磁盘空间。
        with zipfile.ZipFile(source_path) as archive:
            with tempfile.TemporaryDirectory(prefix="pcap_to_dict_") as temp_dir:
                temp_path = Path(temp_dir) / "current_pcap"
                for entry in archive.infolist():
                    entry_suffix = Path(entry.filename).suffix.lower()
                    if entry.is_dir() or entry_suffix not in PCAP_SUFFIXES:
                        continue

                    with archive.open(entry) as input_file:
                        with temp_path.open("wb") as output_file:
                            shutil.copyfileobj(input_file, output_file)

                    _add_pcap_to_dictionary(
                        result, temp_path, entry.filename, networks
                    )
        return result

    if source_path.suffix.lower() in PCAP_SUFFIXES:
        _add_pcap_to_dictionary(
            result, source_path, source_path.name, networks
        )
        return result

    raise ValueError("source 必须是 pcap/pcapng/cap 文件、目录或 zip 文件")


def save_dictionary_as_json(
    result: dict[str, list[str]], output_path: str | Path
) -> None:
    """把 dictionary 保存成便于读取的 JSON 文件。"""
    output = Path(output_path).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as json_file:
        json.dump(result, json_file, ensure_ascii=False, indent=2)


def main() -> None:
    # 直接在 PyCharm 中点击绿色运行按钮时，使用脚本旁边的默认路径。
    script_directory = Path(__file__).resolve().parent
    default_source = script_directory / "splitted_pcap"
    default_output = script_directory / "pcap_result.json"

    parser = argparse.ArgumentParser(
        description="按 UCSB srcIP/dstIP 对 pcap 文件名进行分组"
    )
    parser.add_argument(
        "source",
        nargs="?",
        default=str(default_source),
        help=(
            "pcap 文件、目录或 zip 压缩包；不填写时自动读取脚本旁边的 "
            "splitted_pcap 文件夹"
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        default=str(default_output),
        help="JSON 输出路径；不填写时保存为脚本旁边的 pcap_result.json",
    )
    args = parser.parse_args()

    print(f"正在读取：{Path(args.source).resolve()}")
    result = pcap_to_dictionary(args.source)
    save_dictionary_as_json(result, args.output)
    print(f"处理完成，共找到 {len(result)} 个 UCSB IP。")
    print(f"结果已保存到：{Path(args.output).resolve()}")


if __name__ == "__main__":
    main()
