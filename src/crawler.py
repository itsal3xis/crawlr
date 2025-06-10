import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
import threading
import logging
from datetime import datetime

from db import save_page, mark_visited, is_visited
from utils import can_fetch_robots, detect_js_redirect, analyze_malicious_patterns

logging.basicConfig(
    filename='crawler.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

queue = Queue()
visited_lock = threading.Lock()
total_visited = 0
max_limit = 100

def worker(depth):
    global total_visited
    while not queue.empty():
        url = queue.get()
        with visited_lock:
            if total_visited >= max_limit:
                break
            if is_visited(url):
                continue
            total_visited += 1

        if not can_fetch_robots(url):
            logging.warning(f"Blocked by robots.txt: {url}")
            continue

        try:
            resp = requests.get(url, timeout=10, headers={"User-Agent": "Crawlr/1.0"})
            html = resp.text
            js_redirect = detect_js_redirect(html)
            flags = analyze_malicious_patterns(html)
            save_page(url, resp.status_code, html, js_redirect, flags)
            mark_visited(url)
            logging.info(f"Visited {url} - JS Redirect: {js_redirect is not None} - Malicious: {flags}")
        except Exception as e:
            logging.error(f"Error visiting {url}: {e}")
            continue

        soup = BeautifulSoup(html, 'html.parser')
        for tag in soup.find_all('a', href=True):
            link = urljoin(url, tag['href'])
            if urlparse(link).scheme in ['http', 'https']:
                if not is_visited(link):
                    queue.put(link)


def start_crawl(start_url, depth, limit, verbose=False):
    global max_limit, verbose_mode
    max_limit = limit
    verbose_mode = verbose
    queue.put(start_url)

    with ThreadPoolExecutor(max_workers=5) as executor:
        for _ in range(5):
            executor.submit(worker, depth)

    print(f"[+] Crawling over. URLs crawled : {total_visited}")