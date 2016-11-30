# Usage examples

## Introduction

To use these examples, you obviously need a configured and running Agent-Jones.
The examples are simple curl commands. You can of course call Agent-Jones from any language, provided you can generate REST commands over HTTP and decode JSON.

## Variables used in the examples

Adapt and set these shell variables to get the examples below running.

    export AJ_URL=http://localhost:5000
    export DEVICE=example.device.domain.com
    export AJ_USER=username
    export AJ_PASSWORD=password

## Special ports for SNMP

In case the SNMP agent runs on a custom port, it can be specified as `:portnr` prefix to the devicename.

    export DEVICE=example.device.domain.com:10161

## Looking at the API documentation

Point your browser to $AJ_URL/xdoc/

## Pinging a device

### Request

    curl -X "POST" "$AJ_URL/aj/api/v1/device/$DEVICE/action" \
     -H "Content-Type: multipart/form-data; charset=utf-8" \
     -u "$AJ_USER:$AJ_PASSWORD" \
     -F "type=ping"

### Response

```json
{
    "action": "ping",
    "cmd": "ping -n -t 5 -c 5 -i 0.3 example.device.domain.com",
    "name": "example.device.domain.com",
    "query-duration": 3302,
    "rc": 0,
    "status": "ok",
    "stderr": "",
    "stdout": "PING example.device.domain.com (10.192.250.2): 56 data bytes\n36 bytes from 10.251.5.1: Redirect Host(New addr: 10.251.5.211)\nVr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst\n 4  5  00 0054 8e1c   0 0000  3f  01 d840 10.251.5.143  10.192.250.2 \n\nRequest timeout for icmp_seq 0\n64 bytes from 10.192.250.2: icmp_seq=1 ttl=254 time=3.198 ms\n64 bytes from 10.192.250.2: icmp_seq=2 ttl=254 time=3.236 ms\n64 bytes from 10.192.250.2: icmp_seq=3 ttl=254 time=3.453 ms\n36 bytes from 10.251.5.1: Redirect Host(New addr: 10.251.5.211)\nVr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst\n 4  5  00 0054 bde6   0 0000  3f  01 a876 10.251.5.143  10.192.250.2 \n\n64 bytes from 10.192.250.2: icmp_seq=4 ttl=254 time=4.009 ms\n\n--- example.device.domain.com ping statistics ---\n5 packets transmitted, 4 packets received, 20.0% packet loss\nround-trip min/avg/max/stddev = 3.198/3.474/4.009/0.324 ms\n"
}
```

## Getting a device global information

### Request

    curl -X "GET" "$AJ_URL/aj/api/v1/device/$DEVICE" \
     -u "$AJ_USER:$AJ_PASSWORD"

### Response

```json
{
    "cswMaxSwitchNum": 3,
    "entities": [
        {
            "physicalClass": "stack",
            "physicalDescr": "c38xx Stack",
            "physicalFirmwareRev": "",
            "physicalHardwareRev": "V06",
            "physicalIndex": 1,
            "physicalName": "c38xx Stack",
            "physicalSerialNum": "FCWA94SC0YL",
            "physicalSoftwareRev": ""
        },
        {
            "physicalClass": "chassis",
            "physicalDescr": "WS-C3850-24T-S",
            "physicalFirmwareRev": "0.1",
            "physicalHardwareRev": "V06",
            "physicalIndex": 1000,
            "physicalName": "Switch 1",
            "physicalSerialNum": "FCW1A47J0YL",
            "physicalSoftwareRev": "03.07.01E"
        },
        {
            "physicalClass": "powerSupply",
            "physicalDescr": "Switch 1 - Power Supply A",
            "physicalFirmwareRev": "",
            "physicalHardwareRev": "V01",
            "physicalIndex": 1012,
            "physicalName": "Switch 1 - Power Supply A",
            "physicalSerialNum": "DCB1938H1DN",
            "physicalSoftwareRev": ""
        },
        {
            "physicalClass": "powerSupply",
            "physicalDescr": "Switch 1 - Power Supply B",
            "physicalFirmwareRev": "",
            "physicalHardwareRev": "000",
            "physicalIndex": 1013,
            "physicalName": "Switch 1 - Power Supply B",
            "physicalSerialNum": "",
            "physicalSoftwareRev": ""
        },
        {
            "physicalClass": "module",
            "physicalDescr": "Switch 1 - WS-C3850-24T - Fixed Module 0",
            "physicalFirmwareRev": "",
            "physicalHardwareRev": "",
            "physicalIndex": 1040,
            "physicalName": "Switch 1 Fixed Module 0",
            "physicalSerialNum": "",
            "physicalSoftwareRev": ""
        },
        {
            "physicalClass": "module",
            "physicalDescr": "4x1G Uplink Module",
            "physicalFirmwareRev": "",
            "physicalHardwareRev": "V01",
            "physicalIndex": 1066,
            "physicalName": "Switch 1 FRU Uplink Module 1",
            "physicalSerialNum": "FOC19540NDJ",
            "physicalSoftwareRev": ""
        },
        {
            "physicalClass": "chassis",
            "physicalDescr": "WS-C3850-24T-S",
            "physicalFirmwareRev": "0.1",
            "physicalHardwareRev": "V06",
            "physicalIndex": 2000,
            "physicalName": "Switch 2",
            "physicalSerialNum": "FOC1947U1ZQ",
            "physicalSoftwareRev": "03.07.01E"
        },
        {
            "physicalClass": "powerSupply",
            "physicalDescr": "Switch 2 - Power Supply A",
            "physicalFirmwareRev": "",
            "physicalHardwareRev": "V01",
            "physicalIndex": 2012,
            "physicalName": "Switch 2 - Power Supply A",
            "physicalSerialNum": "DCB194XH1FY",
            "physicalSoftwareRev": ""
        },
        {
            "physicalClass": "powerSupply",
            "physicalDescr": "Switch 2 - Power Supply B",
            "physicalFirmwareRev": "",
            "physicalHardwareRev": "000",
            "physicalIndex": 2013,
            "physicalName": "Switch 2 - Power Supply B",
            "physicalSerialNum": "",
            "physicalSoftwareRev": ""
        },
        {
            "physicalClass": "module",
            "physicalDescr": "Switch 2 - WS-C3850-24T - Fixed Module 0",
            "physicalFirmwareRev": "",
            "physicalHardwareRev": "",
            "physicalIndex": 2040,
            "physicalName": "Switch 2 Fixed Module 0",
            "physicalSerialNum": "",
            "physicalSoftwareRev": ""
        },
        {
            "physicalClass": "module",
            "physicalDescr": "4x1G Uplink Module",
            "physicalFirmwareRev": "",
            "physicalHardwareRev": "V01",
            "physicalIndex": 2066,
            "physicalName": "Switch 2 FRU Uplink Module 1",
            "physicalSerialNum": "FOC19520N1N",
            "physicalSoftwareRev": ""
        },
        {
            "physicalClass": "chassis",
            "physicalDescr": "WS-C3850-24T-S",
            "physicalFirmwareRev": "0.1",
            "physicalHardwareRev": "V06",
            "physicalIndex": 3000,
            "physicalName": "Switch 3",
            "physicalSerialNum": "FOC1142X0YY",
            "physicalSoftwareRev": "03.07.01E"
        },
        {
            "physicalClass": "powerSupply",
            "physicalDescr": "Switch 3 - Power Supply A",
            "physicalFirmwareRev": "",
            "physicalHardwareRev": "V01",
            "physicalIndex": 3012,
            "physicalName": "Switch 3 - Power Supply A",
            "physicalSerialNum": "DCB1948H1DA",
            "physicalSoftwareRev": ""
        },
        {
            "physicalClass": "powerSupply",
            "physicalDescr": "Switch 3 - Power Supply B",
            "physicalFirmwareRev": "",
            "physicalHardwareRev": "000",
            "physicalIndex": 3013,
            "physicalName": "Switch 3 - Power Supply B",
            "physicalSerialNum": "",
            "physicalSoftwareRev": ""
        },
        {
            "physicalClass": "module",
            "physicalDescr": "Switch 3 - WS-C3850-24T - Fixed Module 0",
            "physicalFirmwareRev": "",
            "physicalHardwareRev": "",
            "physicalIndex": 3040,
            "physicalName": "Switch 3 Fixed Module 0",
            "physicalSerialNum": "",
            "physicalSoftwareRev": ""
        }
    ],
    "hwModel": "cat38xxstack",
    "hwVendor": "ciscoSystems",
    "name": "example.device.domain.com",
    "pethMainPsePower": [],
    "query-duration": 2451,
    "sysContact": "somebody",
    "sysDescr": "Cisco IOS Software, IOS-XE Software, Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M), Version 03.07.01E RELEASE SOFTWARE (fc3)\r\nTechnical Support: http://www.cisco.com/techsupport\r\nCopyright (c) 1986-2015 by Cisco Systems, Inc.\r\nCompiled Tue 28-Apr-",
    "sysLocation": "somewhere",
    "sysName": "example.device.domain.com",
    "sysObjectID": "1.3.6.1.4.1.9.1.1745",
    "sysUpTime": 10380910
}
```


## Getting the interface list of a device

### Request

    curl -X "GET" "$AJ_URL/aj/api/v1/interfaces/$DEVICE" \
     -u "$AJ_USER:$AJ_PASSWORD"

Remark: you can add plenty of boolean flags to the request to collect more information and receive them as properties of the response. See the API doc for details.

### Response

In the response, the `physicalIndex` value can be used to identify the enclosing stack member from the list obtained above.

```json
{
    "interfaces": [
        {
            "dot3StatsDuplexStatus": "unknown(1)", 
            "ifAdminStatus": 1, 
            "ifAdminStatusText": "up", 
            "ifAlias": "", 
            "ifDescr": "GigabitEthernet0/0", 
            "ifMtu": 1500, 
            "ifOperStatus": 2, 
            "ifOperStatusText": "down", 
            "ifSpeed": 1000000000, 
            "ifType": "ethernetCsmacd(6)", 
            "index": 1, 
            "physicalIndex": null, 
            "vmVlanNative": {
                "name": null, 
                "nr": 0
            }, 
            "vmVoiceVlanId": {
                "name": null, 
                "nr": 0
            }
        },
        {
            "dot3StatsDuplexStatus": "unknown(1)", 
            "ifAdminStatus": 1, 
            "ifAdminStatusText": "up", 
            "ifAlias": "Clientport 1", 
            "ifDescr": "GigabitEthernet1/0/1", 
            "ifMtu": 1500, 
            "ifOperStatus": 2, 
            "ifOperStatusText": "down", 
            "ifSpeed": 1000000000, 
            "ifType": "ethernetCsmacd(6)", 
            "index": 3, 
            "physicalIndex": 1000, 
            "vmVlanNative": {
                "name": null, 
                "nr": 0
            }, 
            "vmVoiceVlanId": {
                "name": null, 
                "nr": 0
            }
        }, 
        {
            "dot3StatsDuplexStatus": "unknown(1)", 
            "ifAdminStatus": 1, 
            "ifAdminStatusText": "up", 
            "ifAlias": "Clientport 2", 
            "ifDescr": "GigabitEthernet1/0/2", 
            "ifMtu": 1500, 
            "ifOperStatus": 2, 
            "ifOperStatusText": "down", 
            "ifSpeed": 1000000000, 
            "ifType": "ethernetCsmacd(6)", 
            "index": 4, 
            "physicalIndex": 1000, 
            "vmVlanNative": {
                "name": null, 
                "nr": 0
            }, 
            "vmVoiceVlanId": {
                "name": null, 
                "nr": 0
            }
        }
    ], 
    "name": "example.device.domain.com", 
    "query-duration": 2142, 
    "sysName": "example.device.domain.com"
}
```
