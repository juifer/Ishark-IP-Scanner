# IP Scanner

## Description
A multi-threaded proxy scanner that scans IP ranges for open ports and logs accessible addresses.

## Features
- Scans IP ranges from a file
- Multi-threaded for fast scanning
- Logs open IPs to a file
- Displays real-time progress updates
- 
## Installation
Clone the repository using the following command:
```
git clone https://github.com/juifer/Ishark-IP-Scanner.git
cd Ishark-IP-Scanner
```

## Requirements
Make sure you have the required dependencies installed:
```
pip install -r requirements.txt
```


## Usage
Run the script and follow the prompts:
```
python main.py
```

### Input Requirements
- A file containing IP ranges in the format: `START_IP-END_IP`, one per line
- A target port to scan
- Number of threads to use
- Timeout value for connections

### Output
- Open IPs are saved in `open_ips.txt`

## Author
Project coded by **JUIFER**

## License
This project is licensed under the MIT License.

## Repository
GitHub Repository: [Ishark-IP-Scanner](https://github.com/juifer/Ishark-IP-Scanner)
