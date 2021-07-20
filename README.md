# createADLab

This is a powershell script to Configure Active Directory Lab. This script doesn't deploy the machine or install the operating system. You can prepare your operating system and just clone and run this script with all the options configured in the `adConfig.json` file in the same directory as this script. This script currently supports upto 3 Domain Controllers. Two Domain Controllers for the parent domain and a third domain controller for the Child Domain. You can choose to create single, two or three Domain Controllers. Just run the script on each server that you would like to configure as a DC. Additionally it also creates an enterprise admin user as configured in the json file. 

# Sample Config File `adConfig.json`
```json
{
    "totalServers":  "3",
    "domainName":  "example.lab",
    "domainNetBiosName":  "examplelab",
	"childDomainName" : "child"
    "dnsServer":  "192.168.171.254",
    "defaultGateway":  "192.168.171.2",
    "maskBits":  "24",
    "eaUserName":  "eauser",
    "eaPassword":  "MyL@bDCP@ssw0rd",
    "AdminPassword":  "MyL@bDCP@ssw0rd",
    "safeModeAdminPassword":  "MyL@bDCP@ssw0rd",
    "dc1IPAddress":  "192.168.171.254",
    "dc1HostName":  "dc01",
    "dc2IPAddress":  "192.168.171.253",
    "dc2HostName":  "dc02",
    "dc3IPAddress": "192.168.171.252",
    "dc3HostName":  "dc03"
}
```

# How To Run:
Pass the `serverNumber` variable based on which server you are running this script on. 1 for first server, 2 for second server and 3 for third server. 

Examples: 

### On First Server:
```powershell
.\configureADLab -serverNumber 1
```

### Second Server:
```powershell
.\configureADLab -serverNumber 2
```
### Third Server:
```powershell
.\configureADLab --serverNumber 3
```

*Note:* Do not run script upon reboot. It will automatically Continue until the configuration is complete. 

# Features
- Automatically configure AD Lab Environment with Two Domain Controllers and a child domain. 
- Simple configuration with `adConfig.json` file. 
- Auto Resume on Reboot.

# Future Enhancements 
- Add more user , OU creation. 
- Add various active directory misconfigurations 
- Add various AD attack scenarios. 

# Need Help ? 
Please open up an issue if you encounter any issues and I will try to resolve them as and when I can. 

# Want to contribute ? 
Please send a pull request if you add a feature or would like to contribute. 

# Buy me Coffee

<a href="https://www.buymeacoffee.com/akn" target="_blank"><img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee" style="height: 41px !important;width: 174px !important;box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;-webkit-box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;" ></a>

# Youtube Demo and Tutorial
Coming Soon !

