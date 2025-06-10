import os
import sqlite3
import json
from datetime import datetime

# Chemin absolu vers la racine du projet (à adapter si besoin)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, 'crawler.db')  # Un seul fichier crawler.db dans la racine

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS pages (
            id INTEGER PRIMARY KEY,
            url TEXT UNIQUE,
            status_code INTEGER,
            js_redirect TEXT,
            content TEXT,
            malicious_flags TEXT,
            visited_at TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS visited (
            url TEXT PRIMARY KEY,
            visited_at TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_page(url, status_code, content, js_redirect, flags):
    visited_at = datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO pages (url, status_code, js_redirect, content, malicious_flags, visited_at)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (url, status_code, js_redirect, content, json.dumps(flags), visited_at))
    conn.commit()
    conn.close()

def mark_visited(url):
    visited_at = datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT OR REPLACE INTO visited (url, visited_at) VALUES (?, ?)', (url, visited_at))
    conn.commit()
    conn.close()

def is_visited(url):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT 1 FROM visited WHERE url = ?', (url,))
    result = c.fetchone()
    conn.close()
    return result is not None

def clear_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM pages')
    c.execute('DELETE FROM visited')
    conn.commit()
    conn.close()
