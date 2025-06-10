import os
import sqlite3
import argparse
from bs4 import BeautifulSoup
import shutil
import utils

# Determine absolute path to the database
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, os.pardir))
DB_PATH = os.path.join(ROOT_DIR, 'crawler.db')

def get_page_content(url):
    """Fetch the HTML content for a given URL from the database."""
    if not os.path.exists(DB_PATH):
        print(f"[!] Database not found at: {DB_PATH}")
        return None

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT content FROM pages WHERE url = ?", (url,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def terminal_preview(html):
    """Display beautified HTML in the terminal."""
    soup = BeautifulSoup(html, 'html.parser')
    pretty_html = soup.prettify()

    width = shutil.get_terminal_size((80, 20)).columns
    print("\n" + "=" * width)
    print("🕸️  HTML Preview in Terminal")
    print("=" * width + "\n")

    print(pretty_html)
    print("\n" + "=" * width)

def main():
    parser = argparse.ArgumentParser(description="View beautified HTML from crawler.db in the terminal")
    parser.add_argument('--url', required=False, help="Exact URL to view from the database")
    parser.add_argument('--html', action='store_true', help="Display HTML content in the terminal")
    parser.add_argument('--security', action='store_true', help="Display security flags for the URL")
    args = parser.parse_args()
    
    content = get_page_content(args.url)
    if args.html:
        terminal_preview(content)
    elif args.security:
        patterns = utils.analyze_malicious_patterns(content)
        print("\n")
        for pattern, found in patterns.items():
            if found:
                print(f"Pattern found : {pattern}")
        print("\n")

if __name__ == "__main__":
    main()
