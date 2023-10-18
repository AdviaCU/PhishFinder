#other words can be added to feedlist manually but this is to get you started right away.
echo """
 ___________________________________
/____________PhishFinder____________\\
|  ___________________    |   [ON]  |
| |#=================#|   |---------|
| |****PH1\$HF1ND3R****|   | [<] [>] |
| |---->[SIGN IN]<----|   |---------|
| |# Username:_______#|   |  REPORT |
| |# Password:_______#|   |   [X]   |
| |----->[Enter]<-----|   |---------|
| |#=================#|   |  BLOCK  |
| |___________________|   |   [X]   |
|_________________________|_-_-_-_-_|
\____________PhishFinder____________/



"""
#shell prompt asking user to input domain name
echo "Enter the domain name you want to monitor. e.g. adviacu.org"
read domain
touch .secrets
touch dormant_domains.txt
echo EMAIL_USER=noreply@$domain >> .secrets
#shell prompt asking user for SMTP server
echo "Enter the SMTP server. e.g. smtp.office365.com"
read smtp
echo SMTP_SERVER=$smtp >> .secrets
#shell prompt to ask for business name withou spaces
echo "Enter the brand name without spaces. e.g. advia"
read business
touch feedlist.txt
#shell prompt to ask user for recipient email address to receive alerts?
echo "Enter the email address to receive alerts. e.g. web_fraud@adviacu.org"
read email
echo EMAIL_RECIPIENTS=["$email"] >> .secrets
#check if the business is already in the feedlist.txt
if grep -Fxq "$business" feedlist.txt
then
    echo "Brand Name already in the feedlist.txt"
else
    #if not, add it to the feedlist.txt
    echo $business >> feedlist.txt
fi
#split the domain name to get the domain name only without top level domain
domain=$(echo $domain | cut -d"." -f1)
#check if the domain name is already in the watchlist.txt
if grep -Fxq "$domain" feedlist.txt
then
    echo "Domain name already in the feedlist.txt"
else
    #if not, add it to the watchlist.txt
    echo $domain >> feedlist.txt
fi
#run wordtwister.py to get the generate watchlist.txt
python3 wordtwister.py
