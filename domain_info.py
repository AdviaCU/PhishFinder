#!/usr/bin/python3
# ===========================================================
# Author: Oto R.
# Date: September 2023
# Version: 1.0
# Description: PhishFinder - Find high risk domains
# Organization: Advia Credit Union, Information Security Department
# ===========================================================
from socket import gethostbyname
from whois import get_registrar_info
from dns.resolver import resolve  # You may need to install dnspython package
from ipwhois import IPWhois
import logging

logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')

class DomainInfo:
    def __init__(self, domain_name):
        self.domain_name = domain_name
        self.registrar = self.get_registrar_info()    
        self.ip_address = self.get_ip_address()
        self.ip_whois = self.get_ip_whois()
        self.dns_ns_record = self.get_dns_ns_record()
        self.dns_spf_record = self.get_dns_spf_record()
        self.dns_mx_record = self.get_dns_mx_record()
        self.risk_score = self.get_risk_score()

    def to_dict(self):
        return {
            "domain_name": self.domain_name,
            "ip_address": self.ip_address,
            "ip_whois": self.ip_whois,
            "registrar": self.registrar,
            "dns_ns_record": self.dns_ns_record,
            "dns_spf_record": self.dns_spf_record,
            "dns_mx_record": self.dns_mx_record,
            "risk_score": self.risk_score
        }
    
    def get_registrar_info(self):
        logging.info(f"Getting whois info for {self.domain_name}")
        return get_registrar_info(self.domain_name)
    
    def get_ip_address(self):
        logging.info(f"Getting IP address for {self.domain_name}")
        try:
            return gethostbyname(self.domain_name)
        except Exception as e:
            logging.error(e)
            return None

    def get_ip_whois(self):
        logging.info(f"Getting IP Whois for {self.domain_name}")
        ip_address = self.get_ip_address()

        # Check for invalid or private IP addresses
        if (ip_address is None or 
            ip_address.startswith("127.0.0") or 
            ip_address.startswith("10.") or 
            (ip_address.startswith("172.") and int(ip_address.split(".")[1]) in range(16, 32)) or 
            ip_address.startswith("192.168")):
            logging.warning(f"No valid public IP address found for {self.domain_name}. Skipping IP Whois.")
            return None

        try:
            obj = IPWhois(ip_address)
            res = obj.lookup_rdap()
            return res.get('asn_description', None)
        except Exception as e:
            logging.error(f"Error fetching IP Whois for {ip_address}: {str(e)}")
        
        return None

    def get_dns_ns_record(self):
        logging.info(f"Getting NS records for {self.domain_name}")
        try:
            ns_data = resolve(self.domain_name, 'NS')
            return [str(rdata) for rdata in ns_data]
        except Exception as e:
            logging.error(e)
            return None

    def get_dns_spf_record(self):
        logging.info(f"Getting SPF records for {self.domain_name}")
        try:
            txt_data = resolve(self.domain_name, 'TXT')
            txt_data = txt_data.response.to_text()
            txt_data = txt_data.split('\n')
            for line in txt_data:
                if 'v=spf' in line:
                    return line
        except Exception as e:
            logging.error(e)
            return None
    
    def get_dns_mx_record(self):
        logging.info(f"Getting MX records for {self.domain_name}")
        try:
            mx_data = resolve(self.domain_name, 'MX')
            return [str(rdata.exchange) for rdata in mx_data]
        except Exception as e:
            logging.error(e)
            return None
    
    def get_risk_score(self):
        logging.info(f"Getting risk score for {self.domain_name}")
        
        # Constants for risk values.
        RISK_HIGH = 50
        RISK_MEDIUM = 30
        RISK_LOW = 15
        RISK_VERY_LOW = 5
        RISK_NONE = 0
        
        risk = RISK_NONE

        # Registrar and IP information risks.
        if not any([self.registrar, self.ip_address, self.ip_whois, self.dns_ns_record, self.dns_spf_record, self.dns_mx_record]):
            risk += RISK_NONE
        elif "NameSilo" in self.registrar or "Hostinger" in self.registrar or "easyDNS" in self.registrar:
            risk += RISK_HIGH
            risk += RISK_VERY_LOW if not self.ip_address else RISK_MEDIUM
            if "CLOUDFLARE" in (self.ip_whois or ""):
                risk += RISK_HIGH
            else:
                risk += RISK_VERY_LOW
        else:
            risk += RISK_VERY_LOW

        # Domain name risks.
        with open('feedlist.txt', 'r') as f:
            watchlist = f.read().splitlines()
            for x in watchlist:
                x.strip()
                if x == "":
                    continue
                if x in self.domain_name and not self.domain_name.endswith((".com", ".org", ".net")):
                    risk += RISK_HIGH
                
        if self.domain_name.endswith((".com", ".org", ".net")):
            risk += RISK_LOW
        elif self.domain_name.endswith((".ch", ".site", ".online", ".top", ".cc", ".icu", "link", ".info")):
            risk += RISK_HIGH            
        else:
            risk += RISK_MEDIUM

        # DNS Records risks.
        risk += RISK_LOW if self.dns_ns_record else RISK_MEDIUM
        risk += RISK_LOW if self.dns_spf_record else RISK_MEDIUM
        risk += RISK_LOW if self.dns_mx_record else RISK_MEDIUM

        return risk
if __name__ == '__main__':
    domain = "sus_domain_name"
    # Load new domains            
    domain = DomainInfo(domain)
    print(f"Domain: {domain.domain_name}")
    print(f"Registrar: {domain.registrar}")
    print(f"IP Address: {domain.ip_address}")
    print(f"IP Owner: {domain.ip_whois}")
    print(f"Name Servers: {domain.dns_ns_record}")
    print(f"SPF Records: {domain.dns_spf_record}")
    print(f"MX Records: {domain.dns_mx_record}")
    print(f"Risk Score: {domain.risk_score}")
