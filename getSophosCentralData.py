#----------------------------------------------------------------------------
# getSophosCentralData.py
#
# get statistics about alerts, computers and servers from Sophos central.
# connection 
#----------------------------------------------------------------------------
# Created By  : Tiago Coimbra
# Created Date: 26.11.2022
# version = 1.0
# ---------------------------------------------------------------------------
# I took some methods from https://github.com/sophos/PS.Unprotected_Machines
# when I started this script. Thanks to Michael Curtis from Sophos Professional Services.
# ---------------------------------------------------------------------------

import requests
import csv
import configparser
# Import datetime modules
from datetime import date
from datetime import datetime
from datetime import timedelta
#Import OS to allow to check which OS the script is being run on
import os
import json

# Get todays date and time
today = date.today()
now = datetime.now()
time_stamp = str(now.strftime("%d%m%Y_%H-%M-%S"))

#######################
# Sophos Central Code #
#######################

# Get Access Token - JWT in the documentation
def get_bearer_token(client, secret, url):
    d = {
                'grant_type': 'client_credentials',
                'client_id': client,
                'client_secret': secret,
                'scope': 'token'
            }
    request_token = requests.post(url, auth=(client, secret), data=d)
    json_token = request_token.json()
    headers = {'Authorization': str('Bearer ' + json_token['access_token'])}
    return headers

def get_whoami():
    # We now have our JWT Access Token. We now need to find out if we are a Partner or Organization
    # Partner = MSP
    # Organization = Sophos Central Enterprise Dashboard
    # The whoami URL
    whoami_url = 'https://api.central.sophos.com/whoami/v1'
    request_whoami = requests.get(whoami_url, headers=headers)
    whoami = request_whoami.json()
    # MSP or Sophos Central Enterprise Dashboard
    # We don't use this variable in this script. It returns the organization type
    organization_type = whoami["idType"]
    if whoami["idType"] == "partner":
        organization_header= "X-Partner-ID"
    elif whoami["idType"] == "organization":
        organization_header = "X-Organization-ID"
    else:
        organization_header = "X-Tenant-ID"
    organization_id = whoami["id"]
    # The region_url is used if Sophos Central is a tenant
    region_url = whoami.get('apiHosts', {}).get("dataRegion", None)
    return organization_id, organization_header, organization_type, region_url


def read_config():
    config = configparser.ConfigParser()
    config.read('getSophosCentralData.config')
    config.sections()
    client_id = config['DEFAULT']['ClientID']
    client_secret = config['DEFAULT']['ClientSecret']
    
    return(client_id, client_secret)

# get alerts from Sophos Central
def get_Alerts():
    # Add X-Organization-ID to the headers dictionary
    headers[organization_header] = organization_id
    result = requests.get(f"{'https://api-eu02.central.sophos.com/common/v1/alerts'}", headers=headers)
    # Convert to JSON
    result_json = json.loads(result.text)
    #print(json.dumps(result_json, indent=2)) # debug

    return result_json

# get endpoints data from sophos central
def get_Endpoints(type):
    # Add X-Organization-ID to the headers dictionary
    headers[organization_header] = organization_id
    result = requests.get(f"{'https://api-eu02.central.sophos.com/endpoint/v1/endpoints?view=summary&lastSeenAfter=-P30D&pageSize=500&type=' + type}", headers=headers)
    # Convert to JSON
    result_json = json.loads(result.text)
    #print(json.dumps(result_json, indent=2)) # debug

    return result_json

client_id, client_secret = read_config()
token_url = 'https://id.sophos.com/api/v2/oauth2/token'
headers = get_bearer_token(client_id, client_secret, token_url)
organization_id, organization_header, organization_type, region_url = get_whoami()

##################################################################
# Output Json creation
##################################################################
output = {}

stats = {}

alertStats = {}
computerStats = {}
serverStats = {}

##################################################################
# ALERTS
##################################################################
alerts = get_Alerts()

highAlerts = 0
mediumAlerts = 0
lowAlerts = 0

for item in alerts["items"]:
        if item["severity"]=="high":
            highAlerts += 1
        if item["severity"]=="medium":
            mediumAlerts += 1
        if item["severity"]=="low":
            lowAlerts += 1

alertStats = {
    "high" : highAlerts,
    "medium" : mediumAlerts,
    "low" : lowAlerts
}

##################################################################
# Computers
##################################################################
computers = get_Endpoints("computer")

totalComputers = 0
totalComputersOK = 0
totalComputersSuspicious = 0
totalComputersBad = 0
totalComputersUnknown = 0
totalComputersNOTOK = 0
computerOSStats = {}

for item in computers["items"]:
        totalComputers += 1
        if item["health"]["overall"]=="good":
            totalComputersOK += 1
        elif item["health"]["overall"]=="suspicious":
            totalComputersSuspicious += 1
        elif item["health"]["overall"]=="bad":
            totalComputersBad += 1
        elif item["health"]["overall"]=="unknown":
            totalComputersUnknown +=1
        # OS stats
        osVersion = str(item["os"]["name"]) + " " + str(item["os"]["majorVersion"]) + "." + str(item["os"]["minorVersion"]) + "." + str(item["os"]["build"])
        if osVersion in computerOSStats.keys():
            computerOSStats[osVersion] += 1
        else:
             computerOSStats[osVersion] = 1

totalComputersNOTOK = totalComputers - totalComputersOK

computerStats = {
    "total" : totalComputers,
    "good" : totalComputersOK,
    "suspicious" : totalComputersSuspicious,
    "bad" : totalComputersBad,
    "unknown" : totalComputersUnknown,
    "totalnotok" : totalComputersNOTOK,
    "osStats" : computerOSStats
}

##################################################################
# Servers
##################################################################
servers = get_Endpoints("server")

totalServers = 0
totalServersOK = 0
totalServersSuspicious = 0
totalServersBad = 0
totalServersUnknown = 0
totalServersNOTOK = 0
serverOSStats = {}

for item in servers["items"]:
        totalServers += 1
        if item["health"]["overall"]=="good":
            totalServersOK += 1
        elif item["health"]["overall"]=="suspicious":
            totalServersSuspicious += 1
        elif item["health"]["overall"]=="bad":
            totalServersBad += 1
        elif item["health"]["overall"]=="unknown":
            totalServersNOTOK +=1
        # OS stats
        osVersion = str(item["os"]["name"]) + " " + str(item["os"]["majorVersion"]) + "." + str(item["os"]["minorVersion"]) + "." + str(item["os"]["build"])
        if osVersion in serverOSStats.keys():
            serverOSStats[osVersion] += 1
        else:
             serverOSStats[osVersion] = 1

totalServersNOTOK = totalServers - totalServersOK

serverStats = {
    "total" : totalServers,
    "good" : totalServersOK,
    "suspicious" : totalServersSuspicious,
    "bad" : totalServersBad,
    "unknown" : totalServersUnknown,
    "totalnotok" : totalServersNOTOK,
    "osStats" : serverOSStats
}

##################################################################
# Output Json creation
##################################################################
stats = {
    "alerts" : alertStats,
    "computers": computerStats,
    "servers": serverStats
}

output = {
    "stats": stats
}

print(json.dumps(output))