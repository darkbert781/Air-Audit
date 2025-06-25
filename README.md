# Wi-Fi Traffic Analyzer & Security Toolkit

This project is a powerful, menu-driven toolkit for real-time Wi-Fi traffic analysis and network security monitoring. It leverages the capabilities of **Bettercap** and **Scapy** to provide a comprehensive suite of tools for network administrators, security professionals, and enthusiasts.

The system is designed for ease of use, with an automated startup sequence that configures and launches the necessary components, allowing you to go from zero to full network analysis with a single command.

## Key Features

*   **Automated Setup**: A single menu option launches the entire analysis suite, automatically starting the Bettercap engine and the Python-based analyzer in separate terminal windows.
*   **Real-time LAN Monitoring**: Discover all devices connected to the local network and see their IP and MAC addresses.
*   **Unauthorized Device Detection**: Maintain a `whitelist.json` of trusted devices and quickly identify any unauthorized clients on your network.
*   **Live Traffic Classification**: Intercepts and analyzes network traffic in real time, classifying it by type (e.g., Browsing, Streaming, VoIP, Gaming) based on port and protocol heuristics.
*   **Deep Security Analysis**: Integrates directly with the Bettercap API to provide a stream of security-related network events.
*   **Detailed Reporting**: At the end of each session, the tool generates a comprehensive report detailing the traffic breakdown for each device and saves it to `reports.json`.
*   **Packet Capture & Offline Analysis**: Includes options to capture network traffic to a `.pcap` file for later analysis with tools like Wireshark or the built-in analyzer.

## How It Works

The toolkit operates on a three-part architecture:

1.  **The Control Panel (`wifi_monitor.py`):** A user-friendly, menu-driven Python script that serves as the main entry point. It handles user input and orchestrates the launch of the other components.
2.  **The Engine (`bettercap_auto.sh`):** A shell script that automates the setup and execution of Bettercap. It handles dependency checks and configures Bettercap to perform an ARP spoofing attack, enabling it to intercept all local network traffic and expose it via a local API.
3.  **The Analyst (`live_traffic_analyzer.py`):** A Python script that connects to the Bettercap API. It listens to the real-time event stream, processes each packet and event, classifies the traffic, and displays the results in a human-readable format.

## Prerequisites

Before running the toolkit, ensure you have the following dependencies installed on your Linux system:

*   **Python 3**
*   **Bettercap**
*   **Aircrack-ng suite** (specifically `airodump-ng`)
*   **`arp-scan`**
*   **`gnome-terminal`** (for the automated launch feature)

The `bettercap_auto.sh` script will attempt to install Bettercap if it's not found, but it's recommended to install these dependencies beforehand.

## Installation & Setup

1.  **Clone the repository:**
    ```sh
    git clone https://github.com/your-username/your-repo-name.git
    cd your-repo-name
    ```

2.  **Create and activate a Python virtual environment:**
    ```sh
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install the required Python packages:**
    ```sh
    pip install -r requirements.txt
    ```

4.  **Configure your whitelist:**
    Edit the `whitelist.json` file and add the MAC addresses of your authorized devices. This is used by the "Real-time LAN Monitor" to identify unknown clients.
    ```json
    {
      "authorized_macs": [
        "AA:BB:CC:DD:EE:FF",
        "11:22:33:44:55:66"
      ]
    }
    ```

## Usage

To start the application, run the main monitor script:

```sh
python3 wifi_monitor.py
```

This will present you with the main menu. For the full, automated experience, select **option 3, "Live Security Analyzer."**

This will:
1.  Open a new terminal and start the **Bettercap engine**. You may be prompted for your `sudo` password here.
2.  Wait 15 seconds for the engine to initialize.
3.  Open a second terminal and start the **Python analyst**, which will immediately begin displaying live traffic information.

To stop the analysis, simply press `Ctrl+C` in the analyst's terminal window. A final report will be generated and saved.

## Disclaimer

This tool is intended for educational purposes and for network administrators to monitor their own networks. Unauthorized scanning or intercepting of traffic on networks you do not own is illegal. The developers are not responsible for any misuse of this software. Use it responsibly.
