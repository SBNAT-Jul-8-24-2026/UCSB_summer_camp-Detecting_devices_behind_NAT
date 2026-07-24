# UCSB_summer_camp-Detecting_devices_behind_NAT

## Device Detection Behind NAT

A network traffic analysis tool for detecting multiple devices hidden behind a NAT (Network Address Translation). It captures network packets and extracts traffic features to identify individual devices operating behind the same NAT gateway.

## Features

- Packet capture and parsing using **Wireshark / Scapy**
- Network flow feature extraction with **CICFlowMeter**
- Detection of multiple hidden devices behind a single NAT based on traffic features
- Simple command-line entry point to run the full analysis pipeline

## Tech Stack

- **Language**: Python
- **Packet Capture / Parsing**: [Wireshark](https://www.wireshark.org/), [Scapy](https://scapy.net/)
- **Flow Feature Extraction**: [CICFlowMeter](https://www.unb.ca/cic/research/applications.html)

## Requirements

- Python 3.x
- Wireshark (must be installed, with `tshark` available on the command line)
- Python dependencies listed in `requirements.txt`

## Installation

```bash
# Clone the repository
git clone <your-repo-url>
cd <project-directory>

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

> If `requirements.txt` hasn't been generated yet, you can create one with `pip freeze > requirements.txt` or by using `pipreqs`.

## Usage

```bash
python main.py
```

Depending on the script's prompts or configuration options, specify the traffic source (live capture or an existing pcap file). The program will automatically capture (or read) traffic, extract flow features, run device detection, and output the results.

## Project Structure

```
.
├── main.py              # Entry point
├── requirements.txt     # Dependency list
└── ...                  # Other modules/scripts
```

## License

This project currently has no license (No License).
