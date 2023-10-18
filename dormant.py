#!/usr/bin/python3
# ===========================================================
# Author: Oto R.
# Date: September 2023
# Version: 1.0
# Description: PhishFinder - Find high risk domains
# Organization: Advia Credit Union, Information Security Department
# ===========================================================

import os
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import domain_info
from dotenv import load_dotenv
from main import send_email, generate_html

logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
# Get the absolute path of the script
path = os.path.abspath(os.path.dirname(__file__))
# Change the working directory to the script's location
os.chdir(path)
#load enviroment variables
load_dotenv(".secrets")
logging.info(f'Working directory changed to {path}')
naughty_domains = []
domains_to_remove = []
dormant_domains = []

with open('dormant_domains.txt', 'r') as f:
    dormant_domains = f.read().splitlines()

for domain in dormant_domains:
    domain = domain.strip()
    logging.info(f"Getting domain info for {domain}")
    if domain == "":
        continue
    elif domain.startswith("#"):
        continue
    else:
        res = domain_info.DomainInfo(domain).to_dict()
    
        if res['ip_address'] is None:
            logging.warning(f"Skipping {domain} because no IP address was found.")
        elif res['ip_address'] is not None:
            domains_to_remove.append(domain)
            naughty_domains.append(res)

dormant_domains = [d for d in dormant_domains if d not in domains_to_remove]
#convert list to a set and sort by  decending risk score
naughty_domains = sorted(naughty_domains, key=lambda k: k['risk_score'], reverse=True) 
formatted_body = generate_html(naughty_domains)
send_email(formatted_body)

with open('dormant_domains.txt', 'w') as f:
    for domain in dormant_domains:
        if not domain.endswith('\n'):
            domain += '\n'
        f.write(domain)
