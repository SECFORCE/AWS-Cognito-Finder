# AWS Cognito Finder - Burp Suite Extension to find valid AWS Cognito access tokens
# Type : Passive Scanner

# Code Credits:
# Xkeys - Burp Suite Extension to extract interesting strings: https://github.com/vsec7/BurpSuite-Xkeys
# PortSwigger example-scanner-checks: https://github.com/PortSwigger/example-scanner-checks
# Redhunlabs Asset_Discover: https://github.com/redhuntlabs/BurpSuite-Asset_Discover

import json
from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
import re
import base64

class BurpExtender(IBurpExtender, IScannerCheck):

    def	registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("AWS Cognito Finder")
        self._callbacks.registerScannerCheck(self)
        print("Thank you for installing AWS Cognito Finder!")
        return

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if (existingIssue.getUrl() == newIssue.getUrl()):
            return -1
        else:
            return 0
    
    def doPassiveScan(self, baseRequestResponse):        
        request = baseRequestResponse.getRequest()
        response = baseRequestResponse.getResponse()
        requestTokens = self.findCognitoTokens(request.tostring())
        responseTokens = self.findCognitoTokens(response.tostring())
        
        if(len(requestTokens) > 0 or len(responseTokens) > 0):
            return [ScanIssue(baseRequestResponse.getHttpService(), self._helpers.analyzeRequest(baseRequestResponse).getUrl(), [baseRequestResponse], "AWS Cognito Token Found", "Information", (requestTokens, responseTokens))]
        else:
            return None
    
    def findCognitoTokens(self, textToAnalyze):
        aws_regions = ["us-east-2","us-east-1","us-west-1","us-west-2","af-south-1","ap-east-1","ap-southeast-3","ap-south-1","ap-northeast-3","ap-northeast-2","ap-southeast-1","ap-southeast-2","ap-northeast-1","ca-central-1","eu-central-1","eu-west-1","eu-west-2","eu-south-1","eu-west-3","eu-north-1","me-south-1","me-central-1","sa-east-1"]
        cognitoRegex = "(?:eyJ[\w\d\+_\\\\\\-]+\.){2}[\w\d\+_\\\\\\-]+"
        tokens = list()
        for match in re.findall(cognitoRegex, textToAnalyze):
            jwt_payload_raw = match.split(".")[1]
            jwt_payload_padded = jwt_payload_raw + "=" * (len(jwt_payload_raw) % 4)
            payload = json.loads(base64.b64decode(jwt_payload_padded))
            if "scope" in payload and "cognito" in payload["scope"]:
                tokens.append(match)
                aws_region = payload["iss"].split(".")[1]
                for token in tokens:
                    print("Test it out with: "+"aws cognito-idp get-user --region " +aws_region +" --access-token "+ str(token))
                
        return tokens


class ScanIssue(IScanIssue):
    def __init__(self, httpService, url, requestResponseArray, name, severity, tokens):
        self._url = url
        self._httpService = httpService
        self._requestResponseArray = requestResponseArray
        self._name = name
        self._severity = severity
        self._requestTokens, self._responseTokens = tokens

    def getUrl(self):
        return self._url

    def getHttpMessages(self):
        return self._requestResponseArray

    def getHttpService(self):
        return self._httpService

    def getRemediationDetail(self):
        return None

    def getIssueDetail(self):
        issueDetail = "AWS Cognito Token(s) identified<br><br>"
        if len(self._requestTokens) > 0:
            issueDetail += "The following tokens were identified in the request: <br>"
            for token in self._requestTokens:
                issueDetail += "<b>Cognito Token:</b> {}<br>".format(token)
            issueDetail += "<br>"
        if len(self._responseTokens) > 0:
            issueDetail += "The following tokens were identified in the response: <br>"
            for token in self._responseTokens:
                issueDetail += "<b>Cognito Token:</b> {}<br>".format(token)
        return issueDetail

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueType(self):
        return 0

    def getIssueName(self):
        return self._name

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"
