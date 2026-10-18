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
    "Name": "Kong Admin Rest API Unauthorized Access Vulnerability (CVE-2020-11710)",
    "Description": "<p>The Kong API gateway is one of the leading cloud native API gateways today, popular for its rich plugin ecosystem and powerful features. By supporting various plugins such as load balancing, Kong provides developers with highly customizable API management and traffic control solutions.</p><p>When using Docker container as the default configuration to build the Kong API gateway, the unauthenticated Admin Rest API will be opened to the public network by default, allowing attackers to gain unauthorized access to the Admin Rest API and control the Kong API gateway.</p>",
    "Product": "Kongfu",
    "Homepage": "https://konghq.com",
    "DisclosureDate": "2020-04-12",
    "PostTime": "2024-01-16",
    "Author": "2737977997@qq.com",
    "FofaQuery": "body=\"kong_env\"",
    "GobyQuery": "body=\"kong_env\"",
    "Level": "3",
    "Impact": "<p>When using Docker container as the default configuration to build the Kong API gateway, the unauthenticated Admin Rest API will be opened to the public network by default, allowing attackers to gain unauthorized access to the Admin Rest API and control the Kong API gateway.</p>",
    "Recommendation": "<p>1. The default listening ports are 8001 and 8444. It is recommended to set them to be bound locally</p><p>2. If not necessary, public network access to the system is prohibited.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": false,
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
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
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
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Unauthorized Access"
    ],
    "VulType": [
        "Unauthorized Access"
    ],
    "CVEIDs": [
        "CVE-2020-11710"
    ],
    "CNNVD": [
        "CNNVD-202004-611"
    ],
    "CNVD": [
        "CNVD-2020-24138"
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Kong Admin Rest API 未授权访问漏洞（CVE-2020-11710）",
            "Product": "Kong",
            "Description": "<p>Kong API网关是当今领先的云原生API网关之一，以其丰富的插件生态系统和强大的功能而备受欢迎。通过支持负载均衡等多种插件，Kong为开发者提供了高度可定制的API管理和流量控制解决方案。</p><p>默认配置使用 Docker 容器的方式搭建 Kong API 网关时，会在默认情况下将未经鉴权的Admin Rest API 对公网开放，导致攻击者可以通过未授权访问 Admin Rest API，从而控制 Kong API 网关。</p>",
            "Recommendation": "<p>1、默认监听端口是 8001 和 8444 ，建议将其设置为绑定在本地<br></p><p>2、如非必要，禁止公网访问该系统。<br></p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。<br></p>",
            "Impact": "<p>默认配置使用 Docker 容器的方式搭建 Kong API 网关时，会在默认情况下将未经鉴权的 Admin Rest API 对公网开放，导致攻击者可以通过未授权访问 Admin Rest API，从而控制 Kong API 网关。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Kong Admin Rest API Unauthorized Access Vulnerability (CVE-2020-11710)",
            "Product": "Kongfu",
            "Description": "<p>The Kong API gateway is one of the leading cloud native API gateways today, popular for its rich plugin ecosystem and powerful features. By supporting various plugins such as load balancing, Kong provides developers with highly customizable API management and traffic control solutions.</p><p>When using Docker container as the default configuration to build the Kong API gateway, the unauthenticated Admin Rest API will be opened to the public network by default, allowing attackers to gain unauthorized access to the Admin Rest API and control the Kong API gateway.</p>",
            "Recommendation": "<p>1. The default listening ports are 8001 and 8444. It is recommended to set them to be bound locally</p><p>2. If not necessary, public network access to the system is prohibited.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>When using Docker container as the default configuration to build the Kong API gateway, the unauthenticated Admin Rest API will be opened to the public network by default, allowing attackers to gain unauthorized access to the Admin Rest API and control the Kong API gateway.<br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access"
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
    "PocId": "10918"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			inspectRequestConfig := httpclient.NewGetRequestConfig("/")
			inspectRequestConfig.VerifyTls = false
			inspectRequestConfig.FollowRedirect = false
			if resp, _ := httpclient.DoHttpRequest(hostInfo, inspectRequestConfig); resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "X-Kong-Response-Latency") && strings.Contains(resp.Utf8Html, "X-Kong-Admin-Latency") && strings.Contains(resp.Utf8Html, "X-Kong-Upstream-Status") && strings.Contains(resp.Utf8Html, "X-Kong-Proxy-Latency") && strings.Contains(resp.Utf8Html, "X-Kong-Upstream-Latency") {
				stepLogs.VulURL = hostInfo.HostInfo + resp.Request.URL.Path
				return true
			}
			return false
		}, nil,
	))
}
