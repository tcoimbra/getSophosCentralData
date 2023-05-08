# getSophosCentralData
Get statistics about alerts, computers and servers from Sophos Central. use Telegraf, influxDB and Grafana to display a security dashboard. This script was made to display the relevant Sophps Central alerts and stats on a Grafana dashboard.

![alt text](https://raw.githubusercontent.com/tcoimbra/getSophosCentralData/main/screen1.png) 

## script configuration
You need to get the Client ID and Client secret from Sophos Central. Check this page for help: https://developer.sophos.com/getting-started
You need then to set these credentials in the getSophosCentralData.config:
```
[DEFAULT]
ClientID:<client ID from Sophos Central>
ClientSecret:<client secret from Sophos Central>
```

## getSophosCentralData.py script output example 
```json
{
  "stats": {
    "alerts": {
      "high": 0,
      "medium": 0,
      "low": 2
    },
    "computers": {
      "total": 334,
      "good": 323,
      "suspicious": 11,
      "bad": 0,
      "unknown": 0,
      "totalnotok": 11,
      "osStats": {
        "Windows 10 Pro 10.0.18363": 37,
        "Windows 10 Pro 10.0.19045": 217,
        "Windows 10 Pro 10.0.16299": 16,
        "Windows 10 Pro 10.0.17763": 16,
        "Windows 10 Pro 10.0.19042": 35,
        "Windows 10 Pro 10.0.19044": 5,
        "Windows 10 Enterprise 10.0.19045": 2,
        "Windows 10 Pro for Workstations 10.0.17763": 2,
        "Windows 10 Enterprise 10.0.19044": 1
      }
    },
    "servers": {
      "total": 85,
      "good": 85,
      "suspicious": 0,
      "bad": 0,
      "unknown": 0,
      "totalnotok": 0,
      "osStats": {
        "Windows Server 2019 Datacenter 10.0.17763": 13,
        "Windows Server 2019 Standard 10.0.17763": 32,
        "Windows Server 2016 Standard 10.0.14393": 20,
        "Ubuntu 20.04.6 LTS 0.0.0": 4,
        "Windows Server 2012 R2 Standard 6.3.9600": 8,
        "Windows Server 2012 Datacenter 6.2.9200": 3,
        "Ubuntu 22.04.2 LTS 0.0.0": 1,
        "Windows Server 2019 Essentials 10.0.17763": 1
      }
    }
  }
}
```

## Dashboard grafana
Get the grafana dashboard in order to import it here: https://grafana.com/grafana/dashboards/18693

## Telegraf configuration
```
[[inputs.exec]]
 command = "python3 /opt/monitoring/sophosCentralV2/getSophosCentralData.py"
 data_format = "json"
 name_suffix = "_sophoscentral"
 interval = "10m"
 timeout = "120s"
```
## Credits
I took some methods from https://github.com/sophos/PS.Unprotected_Machines when I started this script. Thanks to Michael Curtis from Sophos Professional Services.

## Sources:
- https://github.com/sophos/PS.Unprotected_Machines
- https://developer.sophos.com/getting-started
