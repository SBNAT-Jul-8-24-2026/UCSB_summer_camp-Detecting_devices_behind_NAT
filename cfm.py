from pathlib import Path  # to find the parent directory

import numpy as np  # to handle numerical data
import pandas as pd  # to handle data frames
from cicflowmeter.flow_session import (
    FlowSession,
)  # to extract flow features from packets
from scapy.all import rdpcap  # to read pcap files

base_dir = Path(__file__).resolve().parent
pcap_file = base_dir / "test.pcap"

output_file = base_dir / "flow_features.csv"  # output file
if output_file.exists():  # check if output_file exists
    output_file.unlink()  # remove output_file if it exists
Path(
    base_dir / "flow_features.csv"
).touch()  # create flow_features.csv file if it doesn't exist


def pcap_to_csv(pcap_path: Path, csv_path: Path) -> None:
    FlowSession.output_mode = "csv"  # set output mode to csv
    FlowSession.output = str(csv_path)  # set output path to csv_path

    session = FlowSession()  # create flow session
    for pkt in rdpcap(str(pcap_path)):  # read pcap file
        session.on_packet_received(pkt)  # process packet

    session.garbage_collect(None)  # garbage collect
    del session.output_writer  # delete output writer


pcap_to_csv(pcap_file, output_file)

print("Conversion finished!")

if output_file.stat().st_size == 0:
    print("CSV file is empty, cicflowmeter did not write data, skip reading")
else:
    df = pd.read_csv(output_file)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    print(df.head())
    print(df.shape)
