# 0delay

## Overview

0delay is a Linux-based file transfer system that supports both terminal (CLI) and GUI applications. It provides secure, encrypted file transfers with error correction and user-friendly interfaces.

## Features

- Terminal CLI app written in Python
- GUI app written in Go using Fyne framework
- End-to-end encryption with password protection
- Hamming code error correction for reliable transfers
- SSH-based file sending for CLI app
- Username registration and management via Supabase
- Cross-machine file transfer on Linux
- GitHub Actions CI/CD

## Installation

### Prerequisites

- Python 3.x
- Go 1.20 or later
- Linux operating system
- SSH access and .pem key for remote machines
- Supabase account and project for username management

### Setup

1. Clone the repository:

```bash
git clone https://github.com/Contractor-x/0delay.git
cd 0delay
```

2. Configure Supabase credentials:

Edit `configs/.env` and set your Supabase project URL and anon key.

3. Install Python dependencies:

```bash
pip install -r requirements.txt
```

4. Build the Go GUI app:

```bash
cd cmd/0delay-gui
go mod tidy
go build -o ../../bin/0delay-gui
```

## Usage

### CLI App

Run the terminal app:

```bash
python3 cmd/0delay-cli/0delay.py
```

Follow the prompts to configure and send files.

### GUI App

Run the GUI app:

```bash
./bin/0delay-gui
```

Use the graphical interface to send and receive files.

## Contributing

Contributions are welcome. Please open issues or pull requests on GitHub.

## License

This project is licensed under the MIT License.
