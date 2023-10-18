#!/usr/bin/python3
# ===========================================================
# Author: Oto R.
# Credits: https://github.com/PAST2212/domainthreat
# Date: September 2023
# Version: 1.0
# Description: PhishFinder - Find high risk domains
# Organization: Advia Credit Union, Information Security Department
# ===========================================================

import requests
import zipfile
import base64
import os
import sys
from io import BytesIO
import datetime
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import domain_info
from dotenv import load_dotenv
from collections import OrderedDict
import ast

logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
# Get the absolute path of the script
path = os.path.abspath(os.path.dirname(__file__))
# Change the working directory to the script's location
os.chdir(path)
#load enviroment variables
load_dotenv(".secrets")
logging.info(f'Working directory changed to {path}')

def send_email(body, attachments=None):

    EMAIL_USER = os.getenv("EMAIL_USER")
    recipients = os.getenv("EMAIL_RECIPIENTS")
    recipients = ast.literal_eval(recipients)
    smtp_server = os.getenv("SMTP_SERVER")
    # Create MIMEMultipart object and set email headers
    if EMAIL_USER is None:
        logging.error("EMAIL_USER is not set.")
        return False

    msg = MIMEMultipart()
    msg['From'] = EMAIL_USER
    msg['To'] = ', '.join(recipients)

    # Attach text body
    body = MIMEText(body, 'html')
    msg.attach(body)
    msg['subject'] = "High Risk Domains Report"

    # Convert the MIMEMultipart object to a string to send
    email_str = msg.as_string()

    server = smtplib.SMTP(smtp_server, 25)

    try:
        server.ehlo()
        #server.starttls()
        #server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, recipients, email_str)
        server.close()
        logging.warning("Email sent to sucessfully!")
        return True
    except Exception as e:
        logging.error(f"Email to failed. System encountered an error: {e}")
        return False
    
def download_input_domains():
    print('Downloading the file')
    previous_date_formated = previous_date + '.zip'
    new = base64.b64encode(previous_date_formated.encode('ascii'))
    domain_file = 'https://whoisds.com//whois-database/newly-registered-domains/{}/nrd'.format(new.decode('ascii'))

    try:
        request = requests.get(domain_file, verify=False)
        logging.info('Zip file downloaded the file')
        zipfiles = zipfile.ZipFile(BytesIO(request.content))
        logging.info('Extracting the zip file')
        with zipfiles.open('domain-names.txt') as zf:
            content = zf.read()
            with open(f'{path}/{previous_date}-domain-names.txt', 'wb') as file:
                file.write(content)

    except Exception as e:
        logging.error(e)
        sys.exit(1)

def load_monitored():
    file = open(f'{path}/watched-domain-names.txt', 'r')
    lines = [line.strip() for line in file]
    file.close()
    return lines

def generate_html(high_risk_list):
    html_header = """
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            table {
                border-collapse: collapse;
                width: 100%;
            }
            th, td {
                border: 1px solid black;
                padding: 8px;
                text-align: left;
            }
            th {
                background-color: #f2f2f2;
            }
        </style>
    </head>
    <body>

    <h2>High Risk Domains Report</h2>

    <table>
        <thead>
            <tr>
                <th>Domain Name</th>
                <th>IP Address</th>
                <th>IP Whois</th>
                <th>Registrar</th>
                <th>DNS NS Record</th>
                <th>DNS SPF Record</th>
                <th>DNS MX Record</th>
                <th>Risk Score</th>
            </tr>
        </thead>
        <tbody>
    """
    
    html_rows = ""
    for data in high_risk_list:
        data['domain_name'] = data['domain_name'].replace('.', '[.]')
        row = f"""
            <tr>
                <td>{data['domain_name']}</td>
                <td>{data['ip_address']}</td>
                <td>{data['ip_whois']}</td>
                <td>{data['registrar']}</td>
                <td>{'<br>'.join(data['dns_ns_record']) if isinstance(data['dns_ns_record'], (list, tuple)) else data['dns_ns_record']}</td>
                <td>{data['dns_spf_record'] if data['dns_spf_record'] else "N/A"}</td>
                <td>{data['dns_mx_record'] if data['dns_mx_record'] else "N/A"}</td>
                <td>{data['risk_score']}</td>
            </tr>
        """
        html_rows += row
    
    html_footer = """
    <p>
        Investigate using 
        <a href="https://live.browserstack.com" target="_blank">BrowserStack</a> 
        and report if appropriate.
    </p>
    """
    
    return html_header + html_rows + html_footer

def main(): 
    file_path = f'{path}/{previous_date}-domain-names.txt'
    high_risk_list = []
    if not os.path.exists(file_path):
        logging.info(f'File {file_path} does not exist. Downloading new domains now.')
        download_input_domains()

    if not os.path.exists(f'{path}/{previous_date}-high-risk-domains.html'):
        logging.info(f'HTML File does not exist. Creating new high risk domains file now.')
        naughty_list = []
        watchlist = []
        dlist = []
        dormant_list = []

        with open('watchlist.txt', 'r') as f:
            f = f.readlines()
            for x in f:
                if x == '\n':
                    pass
                else:
                    watchlist.append(x.strip())
            watchlist = list(OrderedDict.fromkeys(watchlist))
            watchlist.sort()
        #open file and parse it for matches of 'advia'
        with open(f'{path}/{previous_date}-domain-names.txt', 'r') as f:
            f = f.readlines()
            for x in f:
                if x == '\n':
                    pass
                else:
                    dlist.append(x.strip())
            dlist = list(OrderedDict.fromkeys(dlist))
            dlist.sort()
        for x in dlist:
            for y in watchlist:
                #logging.warning(f'EVALUATING DOMAIN {x} WATCHLIST: {y}')
                if y in x:
                    naughty_list.append(x)
                    logging.info(f'Suspicious Domain! - Found: {y} - Matched: {x}')
                else:
                    pass
    
        #sort naughty_list alphabetically
        naughty_list = list(OrderedDict.fromkeys(naughty_list))
        naughty_list.sort() 
        for i in naughty_list:
            res = domain_info.DomainInfo(i).to_dict()
            if res["risk_score"] > 100 and res['ip_address'] is not None:
                #pprint(res)
                high_risk_list.append(res)
                logging.info(f'Domain: {i} is a high risk domain!')
            elif res["risk_score"] > 100 and res['ip_address'] is None:
                logging.info(f'Domain: {i} save for future analysis!')
                dormant_list.append(res['domain_name'])
            else:
                logging.info(f'Domain: {i} is not a high risk domain!')
                pass

        #Check to make sure list is not empty
        if len(dormant_list) > 0:
            #sort dormant_list alphabetically
            dormant_list.sort()
            #write dormant_list to file
            with open('dormant_domains.txt', 'a') as f:
                for item in dormant_list:
                    f.write("%s\n" % item)
        
        #convert list to a set and sort by  decending risk score
        high_risk_list = sorted(high_risk_list, key=lambda k: k['risk_score'], reverse=True) 
        formatted_body = generate_html(high_risk_list)
        with open(f'{path}/{previous_date}-high-risk-domains.html', 'w') as f:
            f.write(formatted_body)
        send_email(formatted_body)
        
    else:
        logging.info(f'HTML File exists. Opening File')
        with open(f'{path}/{previous_date}-high-risk-domains.html', 'r') as f:
            formatted_body = f.read()

        send_email(formatted_body)
        logging.info('Email sent successfully!')
        
    #pprint(high_risk_list)
if __name__ == '__main__':
    offset = int(1)
    #set date range for yesterday
    daterange = datetime.datetime.today() - datetime.timedelta(days=offset)
    previous_date = daterange.strftime('20%y-%m-%d')
    main()