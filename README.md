```text
    .n~~%x.      dF                    x .d88"                ..         
  x88X   888.   '88bu.                  5888R                @L          
 X888X   8888L  '*88888bu        .u     '888R         u     9888i   .dL  
X8888X   888888    ^"*8888N    ud8888.    888R      us888u.  `Y888k:*888. 
88888X   88888X  beWE "888L :888'8888.   888R   .@88 "8888"   888E  888I 
88888X   88888X  888E  888E d888 '88%"   888R   9888  9888    888E  888I 
88888X   88888f  888E  888E 8888.+"      888R   9888  9888    888E  888I 
48888X   88888   888E  888F 8888L        888R   9888  9888    888E  888I 
 ?888X   8888"  .888N..888  '8888c. .+  .888B . 9888  9888   x888N><888' 
  "88X   88*`    `"888*""    "88888%    ^*888%  "888*""888"   "88"  888  
    ^"==="`         ""         "YP'       "%     ^Y"   ^Y'          88F  
                                                                   98"   
                                                                 ./"     
                                                                ~`       
```

## Overview

**0delay** is a Linux-based file transfer system that supports both terminal (CLI) and GUI applications. It provides secure, encrypted file transfers with error correction and user-friendly interfaces.

## Features

- Terminal CLI app written in Python
- End-to-end encryption with password protection
- Hamming code error correction for reliable transfers
- SSH-based file sending for CLI app
- Username registration and management via Supabase
- Cross-machine file transfer on Linux
- GitHub Actions CI/CD

## Installation
For installation kindly follow the steps provided

### Prerequisites

- Python 3.1
- Linux operating system
- SSH access and .pem key for remote machines
- Supabase account and project for username management

### Setup

1. Clone the repository:

```bash
sudo dpkg -i 0delay-cli-1.0.0.deb
```

The CLI tool will be installed to `/opt/0delay-cli` with a symlink `/usr/local/bin/0delay-cli`.

Run the tool with:

```bash
0delay-cli
```

## Usage

### CLI App

Run the terminal app:

```bash
python3 cmd/0delay-cli/0delay.py
```

- On startup, the current username (if any) will be displayed.
- The saved username will be displayed.
- You will be prompted to enter or select a target in `username@ip` or IP format.
- You can select or add PEM keys by friendly names.
- The app checks username uniqueness with Supabase and registers silently.
- Transfer history and keys are saved for easy reuse.

Follow the prompts to configure and send files.




- The current username is displayed on entry.
- You can register a new username with uniqueness check.
- Select targets, PEM keys, and files via GUI.
- Transfer history and keys are saved in config.
- Receive files with notifications and prompts.



## Contributing

Contributions are welcome. Please open issues or pull requests on GitHub.

## License

This project is licensed under the MIT License.

## Creators
 Developed by [C0NTRACT0R](https://github.com/Contractor-x/)
