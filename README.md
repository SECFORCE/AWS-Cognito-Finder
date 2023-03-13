# AWS Cognito Finder

## AWS Cognito Finder Burp Suite Extension

To use it, just load the extension on to Burp Suite Professional!
The main behaviour of the extension is that if a JWT token is identified in any HTTP request/response, then it will be checked to see if it's a valid AWS Cognito token. 

If it is, then the extension will create an issue in Burp and also print out an AWS-CLI command ready to copy/paste for getting more info on the AWS Cognito token (this command will be shown in the extension Output console).

### Requirements
Install AWS CLI according to your OS: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html

### Credits
- Xkeys - Burp Suite Extension to extract interesting strings: https://github.com/vsec7/BurpSuite-Xkeys
- PortSwigger example-scanner-checks: https://github.com/PortSwigger/example-scanner-checks
- Redhunlabs Asset_Discover: https://github.com/redhuntlabs/BurpSuite-Asset_Discover

