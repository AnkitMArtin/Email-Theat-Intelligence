#!/usr/bin/env python3
import requests 
import json
import csv
import time
import pycountry

### Getting Current date ###
timestr = time.strftime("%m-%d-%y")

### Feteching IP From File ###
with open('URL.txt')as f :
    content = f.readlines()

length_Content = len(content)
print("Number of Lines in File : " , length_Content)

Counter = 0 

for items in content:
### Virus Total ### 
    API_key = ''  #### ENTER API KEY HERE ####

    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'

    params = {'apikey': API_key, 'ip': items.strip() }

    ip_value = params.get('ip')
    Ip_address = None
    positives = None
    total = None
    country = None

    response = requests.get(url, params=params).json()

    with open("Virus_Total.json", "w") as outfile:
        json.dump(response , outfile , sort_keys=True  , indent = 4)

    IP_found = response['verbose_msg']
    country = response['country']
    check_pycountry = pycountry.countries.get(alpha_2=country)
    country = check_pycountry.name

    for i in response["detected_urls"]: # Checking in Detected Section 
        if ip_value in i.get('url'):
            if i.get('url').endswith("/") :
                
                positives = i.get('positives')
                Ip_address = i.get('url')
                total = i.get('total')

    for i in response["undetected_urls"]: #Checking in Undetected Section 
        if ip_value in str(i) and i[0].endswith("/"):
            Ip_address = i[0]
            positives = i[2]
            total = i[3]        

    MarkDown = f'{IP_found} \nIp Address : {Ip_address} \nIp reputation : {positives } / {total} \nCountry:  {country}  \n'
    with open(f'{timestr}-IP.md', "a") as Readme:
        Readme.write(f'{Counter + 1}Scan result of Virus Total ::\n')
        Readme.write(MarkDown)
        Readme.write('\n')

### AbuseIP DB ###
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': ip_value,
        'maxAgeInDays': '180'
    }

    headers = {
        'Accept': 'application/json',
        'Key': '' ## Enter the API key ##
    }

    response = requests.request(method='GET', url=url, headers=headers, params=querystring)

    #Formatted output
    decodedResponse = json.loads(response.text)
    #print(json.dumps(decodedResponse, sort_keys=True, indent=4))

    IP_Address_abuse = decodedResponse['data'].get('ipAddress')
    Country_abuse  =  decodedResponse['data'].get('countryCode')
    Domain_name_abuse  =  decodedResponse['data'].get('domain')
    Confidence_Score_abuse =  decodedResponse['data'].get('abuseConfidenceScore')
    Total_report_abuse = decodedResponse['data'].get('totalReports')

    MarkDown1 = f'IP Address : {IP_Address_abuse}  \nOriginating Country : {Country_abuse} \nDomain : {Domain_name_abuse} \nIP reputation: {Confidence_Score_abuse} \nReported : {Total_report_abuse} in 180 days  \n'
    with open(f'{timestr}-IP.md', "a") as Readme:
        Readme.write('\n')
        Readme.write("Scan result of Abuse IP db  ::\n")
        Readme.write(MarkDown1)
        Readme.write('\n')

### multirbl.valli.org ###

    multirbl = requests.get('http://multirbl.valli.org/lookup/', params=[('q', ip_value)])
    with open(f'{timestr}-IP.md', "a") as Readme:
        Readme.write("Real-Time IP Blacklisitng Look up   multirbl.valli.org ::\n")
        Readme.write(multirbl.url)
        Readme.write('\n')
        Readme.write('\n')

### CSV Output File ### 
    with open(f'{timestr}-Report.csv', 'a' , newline= '') as csv_file:
        fields=['S.No','Ip Address','Country','Virus Total Ip-reputation' ,'Originating Country AbuseIPDb' , 'Domain Name AbuseIPDb ', 'IP Reputation AbuseIPDb'  , 'IP Reported AbuseIPdb in 180 days ' , 'RBL Report ' ] 
        writer = csv.DictWriter(csv_file,fieldnames= fields)
        writer.writeheader()
        writer.writerow({'S.No': Counter+1 , 'Ip Address': ip_value  ,'Country': country ,'Virus Total Ip-reputation': f"{positives }/{total}" ,'Originating Country AbuseIPDb'  : Country_abuse , 'Domain Name AbuseIPDb ' : Domain_name_abuse, 'IP Reputation AbuseIPDb' : Confidence_Score_abuse , 'IP Reported AbuseIPdb in 180 days ' : Total_report_abuse , 'RBL Report ': multirbl.url })
        