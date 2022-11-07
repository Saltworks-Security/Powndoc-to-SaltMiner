#!/usr/bin/env python


# Need to run the following to make this work
# pip3 install pyyaml
# pip3 install markdownify
import yaml
import markdownify

import json, re


issues = {}
pwnDocFile = 'YOUR PWNDOC FILE HERE' 


####------------------This Code makes the file 'outputTest.json for you to import into saltminer UI------------------####
with open(f"{pwnDocFile}", "r") as stream:
    try:
        
        issues = yaml.safe_load(stream)

        
        print(yaml.safe_load(stream))
    except yaml.YAMLError as exc:
        print(exc)




for issue in issues:
    details = issue["details"][0]

    

    hDescription = details["description"]
    hTitle = details["title"]
    hClassify = details["vulnType"]
    hReferences = details['references']

    
    try:
        hObservation = details['observation']
        mObservation= markdownify.markdownify(hObservation, heading_style='ATX')
        
    except KeyError:
        mObservation = None
    try:
        hSeverity = issue["priority"]
        mSeverity= markdownify.markdownify(str(hSeverity), heading_style='ATX')
        if mSeverity == '1':
            mSeverity='Critical'
        elif mSeverity == '2':
            mSeverity='High'
        elif mSeverity == '3':
            mSeverity='Medium'
        elif mSeverity == '4':
            mSeverity= 'Low'
    #defaulting severity to INFO if no priority is listed    
    except:
        mSeverity= 'Info'
    
    
    try:
         hRecommend =details["remediation"]
         mRecommend = markdownify.markdownify(hRecommend, heading_style="ATX")
         
    except KeyError:
        
        mRecommend= None

    #converting data to markdown 
    mDescription = markdownify.markdownify(hDescription, heading_style="ATX")
    mDescription = re.sub(r'\n', '', mDescription)
    mTitle = markdownify.markdownify(hTitle, heading_style="ATX")
    mClassify = markdownify.markdownify(hClassify, heading_style="ATX")
    mReference = markdownify.markdownify(str(hReferences), heading_style="ATX")

    #jsonTemplate with values inserted 
    jsonIssue = {
        "engagementId": "",
        "engagementName": "",
        "name": mTitle,
        "severity": mSeverity,
        "assetName": None,
        "assetId": "f22cb473-df92-47e4-95b8-f254fbde488d",
        "foundDate": "2022-10-04T00:00:00",
        "testStatus": "Found",
        "isSuppressed": False,
        "isRemoved": False,
        "isActive": True,
        "isFiltered": False,
        "issueId": "7a7b5ef2-a225-4255-96cb-d9b7b85ada97",
        "scanId": "d5ce748b-4838-4c1e-8b0b-216e86e5ce8c",
        "removedDate": None,
        "location": "http://www.saltworks.io",
        "locationFull": "https://www.saltworks.io/home.aspx",
        "isHistorical": False,
        "reportId": "3da331a0-dc55-49b0-bc6e-0d9df27cbbc5",
        "scannerId": "437e9fa2-99b0-4076-a117-867b4b9d7dba",
        "category": [
            "Application"
        ],
        "classification": mClassify,
        "description": mTitle,
        "audited": False,
        "auditor": None,
        "lastAudit": None,
        "enumeration": None,
        "proof": mObservation,
        "testingInstructions": None,
        "details": mDescription,
        "implication": None,
        "recommendation": mRecommend,
        "references": mReference,
        "reference": None,
        "vendor": "Saltworks",
        "product": "Saltworks PenTest",
        "base": 0,
        "environmental": 0,
        "temporal": 0,
        "timestamp": "2022-10-03T19:08:34.4062624-05:00",
        "version": None,
        "attributes": {},
        "attachments": [], 
    } 
    #trying to open existing file
    try:
        with open('outputTest.json', 'r') as file:
            data = json.load(file)
            file.seek(0)


        

    #if file not available writng a new file
    except:
        with open('outputTest.json', 'w') as file:
            base = '[]'
            file.write(base)

        with open('outputTest.json', 'r') as file:
            data = json.load(file)
            file.seek(0)


        
    #either way we end up appending issue to file and exporting out 
    finally:
        data.append(jsonIssue)
        with open('outputTest.json', 'w') as file:
            json.dump(data, file, indent=4)



'''
sample = {'cvssv3': 'CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N', 
    'priority': 1, 
    'remediationComplexity': 1, 
    'category': 'Penetration Test', 
    'details': [
        {'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'], 
        'customFields': [], 
        'locale': 'en', 
        'title': 'Strict transport security not enforced', 
        'vulnType': 'Web Application', 
        'description': "<p>The application fails to prevent users from connecting to it over unencrypted connections. An attacker able to modify a legitimate user's network traffic could bypass the application's use of SSL/TLS encryption, and use the application as a platform for attacks against its users. This attack is performed by rewriting HTTPS links as HTTP, so that if a targeted user follows a link to the site from an HTTP page, their browser never attempts to use an encrypted connection. The sslstrip tool automates this process.</p><p>To exploit this vulnerability, an attacker must be suitably positioned to intercept and modify the victim's network traffic.This scenario typically occurs when a client communicates with the server over an insecure connection such as public Wi-Fi, or a corporate or home network that is shared with a compromised computer. Common defenses such as switched networks are not sufficient to prevent this. An attacker situated in the user's ISP or the application's hosting infrastructure could also perform this attack. Note that an advanced adversary could potentially target any connection made over the Internet's core infrastructure.</p>",
        'remediation': '<p>The application should instruct web browsers to only access the application using HTTPS. To do this, enable HTTP Strict Transport Security (HSTS) by adding a response header with the name \'Strict-Transport-Security\' and the value \'max-age=expireTime\', where expireTime is the time in seconds that browsers should remember that the site should only be accessed using HTTPS. Consider adding the \'includeSubDomains\' flag if appropriate.</p><p>Note that because HSTS is a "trust on first use" (TOFU) protocol, a user who has never accessed the application will never have seen the HSTS header, and will therefore still be vulnerable to SSL stripping attacks. To mitigate this risk, you can optionally add the \'preload\' flag to the HSTS header, and submit the domain for review by browser vendors.</p>'}
        ]}
'''
