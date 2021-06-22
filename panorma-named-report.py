# Simple Python script to retrieve Custom Palo Alto Report from Panorama
# Written for Python3
# Version: 3.7.1
# Sean Engelbrecht

# The process/flow is as follows:
#    - API call to generate an API KEY
#    - API call to generate report
#    - Capture JobID number of report
#    - Check JobID Status on Panorama
#    - If job completes succesfully get report
#    - If job fails, print error

#Not sure if I used all of these, as I grabbed code from other things I have done...

import requests
import xml.etree.ElementTree as ET
import sys
import time
import pan
import pan.xapi
import getpass
import urllib3
import csv
from datetime import datetime

# Variables
gen_api_call = "/api/?type=report&async=yes&reporttype=custom&reportname=" # API URI to generate report
get_api_call = "/api/?type=report&action=get&job-id=" # API uri to get the generated report
# API Key Generated from Panorama for a user with the XML API Permissions
apiKey = ""
# adjust the following variable values as needed to meet your needs
sleep_time = 5 # Time out window for retrieving repoort. Default: 5
time_out = 12 # Time out window in 5 second intervals (5 * 12 = 60seconds)
panorama_server = "" # Panorama FQDN or IP Address
apiAdminUser = "api-admin" # I created a user on Panorama with limited permissions, only XML API - Reports
report_name = "Custom-Web-Usage-Report" # Name of Custom Report created in Panorama

# Error Handeling like a noob
def genErr(errMsg):
    raise RuntimeError(errMsg)
    return 1

# Call API to generate report and capture JobID number of report
def genReport():
    # API call to generate report
    r = requests.get ('https://%s%s%s&key=%s' % (panorama_server, gen_api_call, report_name, apiKey), verify=False)
    # Capture JobID number of report 
    job_root = ET.fromstring(r.content.decode())
    # job_root output: '<response status="success"><result>\n    <msg>\n      <line>Report job enqueued with jobid 116</line>\n    </msg>\n    <job>116</job>\n  </result></response>'
    if "success" in job_root.attrib["status"]:
        global job_id
        job_id = int(job_root.find("result").find("job").text)
        return 0
    else:
        errMsg = "Failed to generate report, API response:\n" + r.content.decode()
        genErr(errMsg)
        return 1

def getPAN_API_Key(apiUser = apiAdminUser):
    ################################################################
    #  Block of code to retrieve API Key if needed
    #  This function can be skipped if you store the API key in the variable (apiKey)
    ##############################################################
    try:
        global apiKey
        apiUser = input('Please enter PAN-OS Admin Account [default: %s]:' % apiAdminUser) or apiAdminUser
        apiUser = apiUser or apiAdminUser
        print('Please enter password for', apiUser)
        # Secure string to input Admin Account Password
        apiPasswd = getpass.getpass()
        # Use Panorama api library to pull new key
        panAPI = pan.xapi.PanXapi(hostname=panorama_server, api_username=apiUser, api_password=apiPasswd)
        apiKey=panAPI.keygen()
        print("API Key Status: %s" % panAPI.status)
    except pan.xapi.PanXapiError as err:
        print("Palo Alto Networks API Call failed.")
        print("  - %s" % str(err).replace("URLError: ",""))
    except:
        print('ERROR: %s' % sys.exc_info()[0])

def sendReport(xml_report):
    ################################################################
    # This block of code can be used to forward the reesulting report to a dataset for automated dashboard updates
    #    - currently all it does is decode and print the results
    ################################################################
    print (xml_report.content.decode())

def getReport():
    # API call to Check JobID Status on Panorama
    get_api_call = "/api/?type=report&action=get&job-id=%s" % job_id
    report = requests.get ('https://%s%s&key=%s' % (panorama_server, get_api_call, apiKey), verify=False)
    report_root = ET.fromstring(report.content.decode())
    job_status = report_root.find("result").find("job").find("status").text
    if "success" in report_root.attrib["status"]:
        i = 0
        loop = True
        while loop:
            if i > time_out:
                errMsg = "Process timed out:\n" + report.content.decode()
                genErr(errMsg)
                break
            if "FIN" in job_status:
                loop = False
                print("***************************")
                print("XML Rport:")
                print("***************************")
                sendReport(report)
                print("***************************")
            else:
                print('Job status: %s retry in 5 sec' % "Pending")
                i += 1
                time.sleep(sleep_time)
                report = requests.get ('https://%s%s&key=%s' % (panorama_server, get_api_call, apiKey), verify=False)
                report_root = ET.fromstring(report.content.decode())
                job_status = report_root.find("result").find("job").find("status").text
    else:
        errMsg = "Failed to generate report, API response:\n" + report.content.decode()
        genErr(errMsg)
        return 1

def main(): 
    try:
        # Suppress SSL Cert Warning message - My lab environmnet uses self-signed certificates
        # remove if necesarry
        requests.packages.urllib3.disable_warnings()
        # API call to generate API Key for the api account
        if len(apiKey) < 1:
            print("API call to retrieve API Key from Panorama...")
            getPAN_API_Key()
        # API call to generate report and capture JobID number of report
        print("API call to generate named report...")
        genReport()
        # API call to Check JobID Status on Panorama
        getReport()
        return 0
    except Exception as err:
        sys.stderr.write('ERROR: %sn' % str(err))
        return 1

if __name__ == "__main__": 
    # calling main function 
    main()
