#!/usr/bin/python3
# ===========================================================
# Author: Oto R.
# Date: September 2023
# Version: 1.0
# Description: PhishFinder - Find high risk domains
# Organization: Advia Credit Union, Information Security Department
# ===========================================================
import socket
import json
import logging

logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')

def query_whois_server(domain, server="whois.iana.org"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((server, 43))
        sock.sendall((domain + "\r\n").encode('utf-8'))
        
        response = b""
        while True:
            data = sock.recv(4096)
            response += data
            if not data:
                break
                
        sock.close()
        return response.decode('utf-8')
    except Exception as e:
        logging.error(e)
        return None

def get_authoritative_server(domain):
    whois_data = query_whois_server(domain)
    for line in whois_data.splitlines():
        if "whois:" in line.lower():
            return line.split(":")[1].strip()
    return None

def get_registrar_info(domain):
    authoritative_server = get_authoritative_server(domain)
    try:
        if authoritative_server:
            whois_result = query_whois_server(domain, server=authoritative_server)
            output_lines = whois_result.splitlines()
            output_dict = {}
            for line in output_lines:
                if ":" in line:  # Check if line contains a colon
                    if "Updated Date:" in line or "Creation Date:" in line:
                        key, value = [x.strip() for x in line.split(":", 1)]
                        output_dict[key] = value
                        
                    if "Registrar" in line and "Please" not in line:
                        key, value = [x.strip() for x in line.split(":", 1)]
                        output_dict[key] = value
            return output_dict["Registrar"]
    except Exception as e:
        logging.error(e)
        return None

if __name__ == "__main__":
    domain = "sus_domain_name"
    result = get_registrar_info(domain)
    json_output = json.dumps(result, indent=4)
    print(json_output)