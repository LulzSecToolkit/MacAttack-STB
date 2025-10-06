# MacAttack-STB

```
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                  ║
║   ███╗   ███╗ █████╗  ██████╗ █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗  ║
║   ████╗ ████║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝  ║
║   ██╔████╔██║███████║██║     ███████║   ██║      ██║   ███████║██║     █████╔╝   ║
║   ██║╚██╔╝██║██╔══██║██║     ██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗   ║
║   ██║ ╚═╝ ██║██║  ██║╚██████╗██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗  ║
║   ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝  ║
║                                                                                  ║
║                    🔥 ULTIMATE PROFESSIONAL EDITION 🔥                           ║
╚══════════════════════════════════════════════════════════════════════════════════╝
```

**Version:** 5.5.0  
**Status:** Active Development

## 📖 Overview

MacAttack-STB is an advanced IPTV testing and management tool designed for professionals. It provides comprehensive MAC address scanning, proxy management, and integrated media playback capabilities with a modern GUI interface.

## ✨ Key Features

### ⚡ Ultra-Fast Scanning
- **Multi-threaded MAC scanning** with up to 100 concurrent threads
- **Concurrent proxy testing** with 100 workers
- Optimized request handling for maximum performance

### 🌐 Proxy Management
- Auto-fetch from 6 free proxy sources
- Ultra-fast testing with socket validation
- Automatic error detection and removal
- Real-time proxy health monitoring

### 📺 Integrated Media Player
- **VLC media player integration** for seamless playback
- Multi-audio track support
- Subtitle management
- Screenshot capture functionality
- Full playback controls

### 💾 Data Management
- Export results to **CSV** and **JSON** formats
- Auto-save settings and configuration
- Favorites system for quick access
- Session history tracking
- Persistent data storage

### 🛠️ Advanced Tools
- MAC address validator
- MAC address generator
- Network information display
- Real-time statistics and analytics
- Performance monitoring

## 🎯 System Requirements

- **Python:** 3.7 or higher
- **VLC Media Player:** Latest version recommended
- **Required Python Libraries:**
  - `python-vlc`
  - `requests`
  - `tkinter` (usually included with Python)

## 📦 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/LulzSecToolkit/MacAttack-STB.git
   cd MacAttack-STB
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Install VLC Media Player:**
   - **Windows:** Download from [videolan.org](https://www.videolan.org/)
   - **Linux:** `sudo apt-get install vlc`
   - **macOS:** `brew install vlc`

4. **Run the application:**
   ```bash
   python macattack.py
   ```

## 🚀 Quick Start

After launching the application, you'll see a multi-tab interface:

### 1. Mac Attack Tab
- Enter or generate MAC addresses
- Configure scanning parameters
- Start multi-threaded scanning
- View and manage results

### 2. Proxies Tab
- Auto-fetch proxies from multiple sources
- Test proxy connectivity and speed
- Remove failed proxies
- Export working proxies

### 3. Player Tab
- Load IPTV streams
- Control playback (play, pause, stop)
- Manage audio tracks and subtitles
- Capture screenshots

### 4. Statistics Tab
- Monitor scan performance
- View success/failure rates
- Track proxy statistics
- Analyze session data

### 5. Settings Tab
- Configure application behavior
- Adjust thread counts
- Set timeout values
- Customize export options

## 📋 Usage Examples

### Basic MAC Scanning
```python
# The GUI provides an intuitive interface for:
# 1. Entering MAC addresses manually
# 2. Generating random MAC addresses
# 3. Importing MAC lists from files
# 4. Starting multi-threaded scans
```

### Proxy Management
```python
# Automatic proxy fetching and testing:
# 1. Click "Fetch Proxies" to download from sources
# 2. Click "Test Proxies" to validate connectivity
# 3. Export working proxies for later use
```

## 🔧 Configuration

The application auto-saves configuration to:
```
~/.config/macattack/config.json
```

Key configuration options:
- Thread count for scanning
- Proxy testing workers
- Timeout values
- Default export format
- VLC player settings

## 📊 Output Formats

### CSV Export
```csv
MAC Address,Status,Portal URL,Timestamp
00:1A:79:XX:XX:XX,Valid,http://portal.example.com,2025-10-06 10:18:27
```

### JSON Export
```json
{
  "mac_address": "00:1A:79:XX:XX:XX",
  "status": "valid",
  "portal_url": "http://portal.example.com",
  "timestamp": "2025-10-06 10:18:27"
}
```

## ⚠️ Disclaimer

This tool is intended for **educational and authorized testing purposes only**. Users are responsible for ensuring they have proper authorization before testing any systems or services. Unauthorized access to computer systems is illegal.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

This project is provided as-is for educational purposes.

## 👤 Author

**LulzSecToolkit**
**@Lulz1337**

## 🔄 Version History

- **v5.5.0** (Current) - Ultimate Professional Edition
  - Multi-threaded scanning (100 threads)
  - Enhanced proxy management
  - Integrated VLC player
  - Advanced statistics
  - CSV/JSON export

## 📧 Support

For issues, questions, or feature requests, please open an issue on GitHub.

---

**Made with ❤️ by LulzSecToolkit**
```

This README provides comprehensive documentation for MacAttack-STB application, including all the features in the application output.
