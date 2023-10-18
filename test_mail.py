#!/usr/bin/python3
from main import send_email
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
def main():
    try:
        with open('replace_html_filename', 'r') as f:
            send_email("replace_with_your_email", f.read())
    except Exception as e:
        logging.error(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
