# **PhishFinder**  
```
 ___________________________________
/____________PhishFinder____________\
|  ___________________    |   [ON]  |
| |#=================#|   |---------|
| |****PH1$HF1ND3R****|   | [<] [>] |
| |---->[SIGN IN]<----|   |---------|
| |# Username:_______#|   |  REPORT |
| |# Password:_______#|   |   [X]   |
| |----->[Enter]<-----|   |---------|
| |#=================#|   |  BLOCK  |
| |___________________|   |   [X]   |
|_________________________|_-_-_-_-_|
\____________PhishFinder____________/

- Copyright (c) - 2023 Advia Credit Union -  

```  
PhishFinder is a Python tool that monitors new domain registrations, performs basic OSINT, and assigns risk scores based on select parameters. Ideal for finding fradulent web impersonators, set it up as a daily cronjob! it can also generate and email risk reports. It relies on the [Whois DS](https://www.whoisds.com/newly-registered-domains) free dataset.   

## **Features**  

- Downloads new domain registrations from WhoisDS.com.  
- Matches domains with watchlist.txt or feedlist.txt and assigns risk scores.  
- Emails a list of high-risk domains.  
- Logs unresolved high-risk domains in dormant_domains.txt. 

## **Installation & Usage**  
1. Clone the repository.  
2. Execute `pip3 install -r requirements.txt`.  
3. Run `setup.sh`.  
4. Start with `python3 main.py`.  

## **Contributing**  

1. Fork the project.  
2. Create your feature branch (`git checkout -b feature/NewFeature`).  
3. Commit your changes (`git commit -am 'Add NewFeature'`).  
4. Push to the branch (`git push origin feature/NewFeature`).  
5. Open a pull request.  

## **License**  

See the [LICENSE](LICENSE.md) file for details.  

## **Acknowledgements**  

- [PAST2212's domaintreat](https://github.com/PAST2212/domainthreat)  
- [elceef's dnstwist](https://github.com/elceef/dnstwist/tree/master)  
