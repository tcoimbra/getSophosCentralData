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
    try:
        request_token = requests.post(url, auth=(client, secret), data=d)
        request_token.raise_for_status()  # Raises an error for bad responses
        json_token = request_token.json()
        headers = {'Authorization': 'Bearer ' + json_token['access_token']}
    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error during token request: {e}")
        return None  # Indicates failure to get token
    except ValueError as e:
        print(f"Error decoding JSON during token request: {e}")
        return None  # JSON decoding error
    return headers

def get_whoami():
    whoami_url = 'https://api.central.sophos.com/whoami/v1'
    try:
        request_whoami = requests.get(whoami_url, headers=headers)
        request_whoami.raise_for_status()  # Raises HTTPError for bad responses
        whoami = request_whoami.json()
        
        organization_type = whoami.get("idType", "unknown")
        organization_header = {
            "partner": "X-Partner-ID",
            "organization": "X-Organization-ID"
        }.get(organization_type, "X-Tenant-ID")
        
        organization_id = whoami.get("id", "unknown")
        region_url = whoami.get('apiHosts', {}).get("dataRegion", None)

    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error: {e}")
        return None, None, None, None
    except ValueError as e:
        print(f"Error decoding JSON: {e}")
        return None, None, None, None
    return organization_id, organization_header, organization_type, region_url

def read_config():
    config = configparser.ConfigParser()
    try:
        config.read('getSophosCentralData.config')
        client_id = config['DEFAULT']['ClientID']
        client_secret = config['DEFAULT']['ClientSecret']
    except KeyError as e:
        print(f"Missing required configuration key: {e}")
        return None, None  # Indicates failure to read configuration
    except configparser.Error as e:
        print(f"Error reading configuration: {e}")
        return None, None  # General configuration error indicator
    return client_id, client_secret

# get alerts from Sophos Central
def get_Alerts():
    headers[organization_header] = organization_id
    response = requests.get("https://api-eu02.central.sophos.com/common/v1/alerts", headers=headers)
    if response.status_code != 200:
        print(f"Error fetching alerts: HTTP {response.status_code}")
        print("Response:", response.text)
        return {}  # or return an appropriate value indicating failure
    try:
        result_json = response.json()
        if "items" not in result_json:
            print("Unexpected JSON format. 'items' key not found.")
            print("Response JSON:", json.dumps(result_json, indent=2))
            return {}  # or return an appropriate value indicating the issue
        return result_json
    except ValueError as e:
        print("Failed to decode JSON response:", e)
        return {}  # or return an appropriate value indicating the issue

# get endpoints data from sophos central
def get_Endpoints(endpoint_type):
    headers[organization_header] = organization_id
    # Assuming `region_url` can be used to construct the full URL dynamically. If not applicable, adjust accordingly.
    base_url = region_url if region_url else "https://api-eu02.central.sophos.com"
    request_url = f"{base_url}/endpoint/v1/endpoints?view=summary&lastSeenAfter=-P30D&pageSize=500&type={endpoint_type}"
    
    response = requests.get(request_url, headers=headers)
    
    if response.status_code != 200:
        print(f"Error fetching {endpoint_type} endpoints: HTTP {response.status_code}")
        print("Response:", response.text)
        return {}  # or an appropriate value indicating failure

    try:
        result_json = response.json()
        if "items" not in result_json:
            print(f"Unexpected JSON format for {endpoint_type} endpoints. 'items' key not found.")
            print("Response JSON:", json.dumps(result_json, indent=2))
            return {}  # or an appropriate value indicating the issue
        return result_json
    except ValueError as e:
        print(f"Failed to decode JSON response for {endpoint_type} endpoints:", e)
        return {}  # or an appropriate value indicating the issue

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
