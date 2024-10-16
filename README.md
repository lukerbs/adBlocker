
# Adblocker Proxy Monitoring Script (Work In Progress)

This Python script (`adblocker.py`) is designed to monitor Chrome's network connections and route traffic through a SOCKS5 proxy. The script leverages several key libraries such as `psutil`, `socket`, and `ipwhois` to monitor and manage network traffic. Additionally, it uses a WHOIS lookup feature to provide detailed information about IP addresses. 

### Key Features:
- **Adblocker**: Downloads a blacklist of ad servers and helps identify unwanted connections.
- **SOCKS5 Proxy**: Routes Chrome traffic through a SOCKS5 proxy for enhanced privacy.
- **WHOIS Lookup**: Performs WHOIS lookups on IP addresses to gather ownership and network information.
- **Chrome Connection Monitoring**: Monitors Chrome's network connections in real-time and blocks or allows connections as specified.

### Current Functionality:
1. **Download Ad Server Blacklist**: Downloads and parses a list of ad servers from a predefined URL.
2. **SOCKS5 Proxy Setup**: Configures a SOCKS5 proxy that redirects traffic from Chrome.
3. **Chrome Network Monitor**: Monitors Chrome's network connections to identify and intercept traffic.
4. **IP and Domain Lookup**: Resolves IP addresses to domain names and provides WHOIS information for further analysis.

### Project Structure:
```
├── .gitignore
├── LICENSE
├── adblocker.py
└── requirements.txt
```

### How to Use:
1. **Install the required dependencies**:
    ```
    pip install -r requirements.txt
    ```
2. **Run the script**:
    ```
    python adblocker.py
    ```

### Dependencies:
- `psutil`
- `ipwhois`
- `requests`
- `socks`

You can install these dependencies by running:
```
pip install -r requirements.txt
```

### TODO:
- Set up local `mitmproxy` to intercept and modify responses.
- Add more detailed logic for routing Chrome connections.
- Implement further optimizations for blocking unwanted traffic.

### License:
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.

### Disclaimer:
This is a work in progress and should be used for educational purposes only. Use this script at your own risk.
