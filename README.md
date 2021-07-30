# Email Threat Intelligence
------

This is project is about verify communicated IP reputation with different IP reputation website . 

In this project I used Virus Total , AbuseIPDb , multirbl.valli.org  to check IP reputation report . 

**Virus Total (VT)**:
- To get  API key for 'Virus Total'  You have to go to [Virus  Total.com](https://www.virustotal.com/) and register with your email Id.
- You can  choose free version , but If your requirement  exceed more than free version virus total provide premium version with a fee. 
-  You copy the API Key and paste it in required section  inthe code . **Do Not add any space while copy paste api key** 
- Here I get verdict  of  IP  repuatation and Country origin  through VT API calls . You can checkout  [VT API Doccumentation](https://developers.virustotal.com/) for more information.

**AbuseIPDb**:

- Sign-UP in [AbuseIpdb](https://abuseipdb.com/) to get your API key . 
- Here I get Originating Country , Domain Name , IP Confidence , Reported  for  the IP in API  Call. 
- **maxAgeInDays** variable you can change the value in  how many days  Ip has reported  . **Default value is 180 days in code**.
- You can check out [API documentation](https://docs.abuseipdb.com/) for reference.

**multirbl.valli**
: multirbl.valli this weebsite will give you  summary report  of IP DNSBL. 

### Code :
-  Before run the code You have to create a file name **URL.txt** and Paste all your IP in the file.
-  For Install dependency Pip install requirement.txt 
-  Output file will be created with .md and .csv

**Noted Below :** 
**At the end of the Ip list in URL.txt file . Please check and removed any empty line.** 














