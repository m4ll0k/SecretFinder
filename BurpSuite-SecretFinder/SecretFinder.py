#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# SecretFinder: Burp Suite Extension to find and search apikeys/tokens from a webpage 
# by m4ll0k
# https://github.com/m4ll0k

# Code Credits:
# OpenSecurityResearch CustomPassiveScanner: https://github.com/OpenSecurityResearch/CustomPassiveScanner
# PortSwigger example-scanner-checks: https://github.com/PortSwigger/example-scanner-checks
# https://github.com/redhuntlabs/BurpSuite-Asset_Discover/blob/master/Asset_Discover.py

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array
import re
import binascii
import base64
import xml.sax.saxutils as saxutils


class BurpExtender(IBurpExtender, IScannerCheck):
    def	registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._callbacks.setExtensionName("SecretFinder")
        self._callbacks.registerScannerCheck(self)
        return

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if (existingIssue.getIssueDetail() == newIssue.getIssueDetail()):
            return -1
        else:
            return 0

    # add your regex here
    regexs = {
        'google_api' : 'AIza[0-9A-Za-z-_]{35}',
        'docs_file_exetension' : '^.*\.(xls|xlsx|doc|docx)$',
        'bitcoin_address' : '([13][a-km-zA-HJ-NP-Z0-9]{26,33})',
        'slack_api_key' : 'xox.-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}',
        'us_cn_zipcode' : '/(^\d{5}(-\d{4})?$)|(^[ABCEGHJKLMNPRSTVXY]{1}\d{1}[A-Z]{1} *\d{1}[A-Z]{1}\d{1}$)/',
        'google_cloud_platform_auth' : '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
        'google_cloud_platform_api' : '[A-Za-z0-9_]{21}--[A-Za-z0-9_]{8}',
        'amazon_secret_key' : '[0-9a-zA-Z/+]{40}',
        'gmail_auth_token' : '[0-9(+-[0-9A-Za-z_]{32}.apps.qooqleusercontent.com',
        'github_auth_token' : '[0-9a-fA-F]{40}',
        'Instagram_token' : '[0-9a-fA-F]{7}.[0-9a-fA-F]{32}',
        'twitter_access_token' : '[1-9][ 0-9]+-(0-9a-zA-Z]{40}',
        'firebase' : 'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
        'google_captcha' : '6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
        'google_oauth' : 'ya29\.[0-9A-Za-z\-_]+',
        'amazon_aws_access_key_id' : 'AKIA[0-9A-Z]{16}',
        'amazon_mws_auth_toke' : 'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        'amazon_aws_url' : 's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
        'facebook_access_token' : 'EAACEdEose0cBA[0-9A-Za-z]+',
        'authorization_basic' : 'basic\s*[a-zA-Z0-9=:_\+\/-]+',
        'authorization_bearer' : 'bearer\s*[a-zA-Z0-9_\-\.=:_\+\/]+',
        'authorization_api' : 'api[key|\s*]+[a-zA-Z0-9_\-]+',
        'mailgun_api_key' : 'key-[0-9a-zA-Z]{32}',
        'twilio_api_key' : 'SK[0-9a-fA-F]{32}',
        'twilio_account_sid' : 'AC[a-zA-Z0-9_\-]{32}',
        'twilio_app_sid' : 'AP[a-zA-Z0-9_\-]{32}',
        'paypal_braintree_access_token' : 'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
        'square_oauth_secret' : 'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
        'square_access_token' : 'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
        'stripe_standard_api' : 'sk_live_[0-9a-zA-Z]{24}',
        'stripe_restricted_api' : 'rk_live_[0-9a-zA-Z]{24}',
        'github_access_token' : '[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
        'rsa_private_key' : '-----BEGIN RSA PRIVATE KEY-----',
        'ssh_dsa_private_key' : '-----BEGIN DSA PRIVATE KEY-----',
        'ssh_dc_private_key' : '-----BEGIN EC PRIVATE KEY-----',
        'pgp_private_block' : '-----BEGIN PGP PRIVATE KEY BLOCK-----',
        'json_web_token' : 'ey[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*|ey[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*'
    }
    regex = r"[:|=|\'|\"|\s*|`|´| |,|?=|\]|\|//|/\*}](%%regex%%)[:|=|\'|\"|\s*|`|´| |,|?=|\]|\}|&|//|\*/]"
    issuename = "SecretFinder: %s"
    issuelevel = "Information"
    issuedetail = r"""Potential Secret Find: <b>%%regex%%</b>
    <br><br><b>Note:</b> Please note that some of these issues could be false positives, a manual review is recommended."""

    def doActiveScan(self, baseRequestResponse,pa):
        scan_issues = []
        tmp_issues = []

        self._CustomScans = CustomScans(baseRequestResponse, self._callbacks)


        for reg in self.regexs.items():
            tmp_issues = self._CustomScans.findRegEx(
                BurpExtender.regex.replace(r'%%regex%%',reg[1]), 
                BurpExtender.issuename%(' '.join([x.title() for x in reg[0].split('_')])),
                BurpExtender.issuelevel, 
                BurpExtender.issuedetail
                )
            scan_issues = scan_issues + tmp_issues

        if len(scan_issues) > 0:
            return scan_issues
        else:
            return None

    def doPassiveScan(self, baseRequestResponse):
        scan_issues = []
        tmp_issues = []

        self._CustomScans = CustomScans(baseRequestResponse, self._callbacks)


        for reg in self.regexs.items():
            tmp_issues = self._CustomScans.findRegEx(
                BurpExtender.regex.replace(r'%%regex%%',reg[1]),
                BurpExtender.issuename%(' '.join([x.title() for x in reg[0].split('_')])), 
                BurpExtender.issuelevel,
                BurpExtender.issuedetail
                )
            scan_issues = scan_issues + tmp_issues

        if len(scan_issues) > 0:
            return scan_issues
        else:
            return None

class CustomScans:
    def __init__(self, requestResponse, callbacks):
        self._requestResponse = requestResponse
        self._callbacks = callbacks
        self._helpers = self._callbacks.getHelpers()
        self._mime_type = self._helpers.analyzeResponse(self._requestResponse.getResponse()).getStatedMimeType()
        return

    def findRegEx(self, regex, issuename, issuelevel, issuedetail):
        print(self._mime_type)
        if '.js' in str(self._requestResponse.getUrl()):
            print(self._mime_type)
            print(self._requestResponse.getUrl())
        scan_issues = []
        offset = array('i', [0, 0])
        response = self._requestResponse.getResponse()
        responseLength = len(response)

        if self._callbacks.isInScope(self._helpers.analyzeRequest(self._requestResponse).getUrl()):
            myre = re.compile(regex, re.VERBOSE)
            encoded_resp=binascii.b2a_base64(self._helpers.bytesToString(response))
            decoded_resp=base64.b64decode(encoded_resp)
            decoded_resp = saxutils.unescape(decoded_resp)

            match_vals = myre.findall(decoded_resp)

            for ref in match_vals:
                url = self._helpers.analyzeRequest(self._requestResponse).getUrl()
                offsets = []
                start = self._helpers.indexOf(response,
                                    ref, True, 0, responseLength)
                offset[0] = start
                offset[1] = start + len(ref)
                offsets.append(offset)

                try:
                    print("%s : %s"%(issuename.split(':')[1],ref))
                    scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace(r"%%regex%%", ref)))
                except:
                    continue
        return (scan_issues)

class ScanIssue(IScanIssue):
    def __init__(self, httpservice, url, requestresponsearray, name, severity, detailmsg):
        self._url = url
        self._httpservice = httpservice
        self._requestresponsearray = requestresponsearray
        self._name = name
        self._severity = severity
        self._detailmsg = detailmsg

    def getUrl(self):
        return self._url

    def getHttpMessages(self):
        return self._requestresponsearray

    def getHttpService(self):
        return self._httpservice

    def getRemediationDetail(self):
        return None

    def getIssueDetail(self):
        return self._detailmsg

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
        return "Tentative"
