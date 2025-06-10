import argparse
from db import init_db
from crawler import start_crawl

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Cybersecurity Web Crawler")
    parser.add_argument('--url', type=str, required=True, help='URL de départ')
    parser.add_argument('--depth', type=int, default=2, help='Profondeur de crawl')
    parser.add_argument('--limit', type=int, default=100, help='Nombre maximum d’URLs à explorer')
    parser.add_argument('--verbose', action='store_true', help='Afficher les logs en temps réel')
    args = parser.parse_args()

    init_db()
    start_crawl(args.url, args.depth, args.limit, args.verbose)

