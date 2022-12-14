
import "elf"

rule Alchimist_Insekt_ELF_32
{
	meta:
	    author = "Yakov Goldberg"
	    date = "2022-11-15"
	    description = "Detect the Linux Alchimist Insekt Implants and Framework binaries"
	    hash1 = "3329dc95c8c3a8e4f527eda15d64d56b3907f231343e97cfe4b29b51d803e270" //Variant x32 - Cisco
	    hash2 = "57e4b180fd559f15b59c43fb3335bd59435d4d76c4676e51a06c6b257ce67fb2" //Variant x32 - Cisco
	    hash3 = "16294086be1cc853f75e864a405f31e2da621cb9d6a59f2a71a2fca4e268b6c2" //Variant x32 - Threat hunting - Similar to 3329dc95c8c3a8e4f527eda15d64d56b3907f231343e97cfe4b29b51d803e270
	    os = "ELF x32"
	    reference = "https://blog.talosintelligence.com/alchimist-offensive-framework/" 
	    OS = "ELF 32-bit LSB executable"
	    version="1.0"
	strings:
		/* Go Build Signature */
        $x1 = "Go build" wide ascii nocase
        $x2 = "golang.org/x/sys" wide ascii nocase

		$s1 = "github.com/fatedier/frp/client/proxy.TcpProxy"
        $s2 = "frp/cmd/frpc/sub/xtcp.go"
        $s3 = "frp/client/proxy/proxy_manager.go"
        $s4 = "fatedier/frp/models/config/proxy.go"
        $s5 = "github.com/fatedier/frp/server/proxy"
        $s6 = "frp/cmd/frps/main.go"
        $s7 = "crypto"
        $s8 = "websocket"
        $s9 = "json:\"remote_port\""
        $s10 = "remote_port"
        $s11 = "remote_addr"
        $s12 = "range section [%s] local_port and remote_port is necessary[ERR]"

        /*
		81 34 24 00 00 20 00                    xor     [esp+90h+var_90], 200000h
		9D                                      popf
		9C                                      pushf
		58                                      pop     eax
		33 04 24                                xor     eax, [esp+8Ch+var_8C]
		9D                                      popf
		A9 00 00 20 00                          test    eax, 200000h
		75 2D   								jnz     short loc_80AD9B4
        */

        $op1 = { 81 34 24 ?? ?? ?? ?? 9d 9c 58 33 04 24 9d a9 ?? ?? ?? ?? 75 2d }

        /* From 3329dc95c8c3a8e4f527eda15d64d56b3907f231343e97cfe4b29b51d803e270
		B8 00 00 00 00                          mov     eax, 0
		0F A2                                   cpuid
		89 C6                                   mov     esi, eax
		83 F8 00                                cmp     eax, 0
		74 36                                   jz      short loc_80AD9F8
		81 FB 47 65 6E 75                       cmp     ebx, 756E6547h
		75 17                                   jnz     short loc_80AD9E1
		81 FA 69 6E 65 49                       cmp     edx, 49656E69h
		75 0F                                   jnz     short loc_80AD9E1
		81 F9 6E 74 65 6C                       cmp     ecx, 6C65746Eh
		75 07                                   jnz     short loc_80AD9E1
		C6 05 08 41 CF 08 01                    mov     ds:byte_8CF4108, 1
        */

        /* From 16294086be1cc853f75e864a405f31e2da621cb9d6a59f2a71a2fca4e268b6c2
 
		B8 00 00 00 00                          mov     eax, 0
		0F A2                                   cpuid
		89 C6                                   mov     esi, eax
		83 F8 00                                cmp     eax, 0
		74 3D                                   jz      short loc_80A71DF
		81 FB 47 65 6E 75                       cmp     ebx, 756E6547h
		75 1E                                   jnz     short loc_80A71C8
		81 FA 69 6E 65 49                       cmp     edx, 49656E69h
		75 16                                   jnz     short loc_80A71C8
		81 F9 6E 74 65 6C                       cmp     ecx, 6C65746Eh
		75 0E                                   jnz     short loc_80A71C8
		C6 05 48 2F 88 08 01                    mov     ds:byte_8882F48, 1
        */

        $op2 = {b8 00 00 00 00 0f a2 89 c6 83 f8 00 74 ?? 81 fb 47 65 6e 75 75 ?? 81 fa 69 6e 65 49 75 ?? 81 f9 6e 74 65 6c 75 ?? c6 05 ?? ?? ?? ?? ?? }

        /* From 3329dc95c8c3a8e4f527eda15d64d56b3907f231343e97cfe4b29b51d803e270
		B8 01 00 00 00                          mov     eax, 1
		0F A2                                   cpuid
		89 CF                                   mov     edi, ecx
		89 05 54 42 CF 08                       mov     ds:dword_8CF4254, eax
		F7 C2 00 00 80 00                       test    edx, 800000h
		74 8F                                   jz      short loc_80AD987
        */

        /* From 16294086be1cc853f75e864a405f31e2da621cb9d6a59f2a71a2fca4e268b6c2
		B8 01 00 00 00                          mov     eax, 1
		0F A2                                   cpuid
		89 CF                                   mov     edi, ecx
		89 05 54 30 88 08                       mov     ds:dword_8883054, eax
		F7 C2 00 00 80 00                       test    edx, 800000h
		74 88                                   jz      short loc_80A7167
        */
        $op3 = {b8 01 00 00 00 0f a2 89 cf 89 05 54 ?? ?? ?? f7 c2 ?? ?? ?? ?? 74 ?? }

    condition:
        elf.machine == elf.EM_386 and ( 
        		any of ($x*) and (
        			7 of ($s*) or all of ($op*)
        		)
        	)
}
	    