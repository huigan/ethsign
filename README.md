# EthSign

## 此代码库为以太坊中使用metamask等钱包生成的签名的验证。
##步骤1 前端传值 签名、消息字符、地址。如下：

sign: 里面包含三部分，分别是：r s v，无需自己解析，传入后代码会自动解析。例如：0xb319edba9d9d8c12a83d3a6e2a072fa5813dd8a5e9460ac3a475ab40a9988ddd059eed15f8c748a2b18c303b2a290a40c464b0a72274dfe1a96820bb02617b4f1b

msg: 为签名字符串。 例如：123456

address: 签名地址。 例如：0xc9fa719138a0d8fec944ed2bdc6d191e3ef08721



##步骤2 后端拿到上面的三个值进行验证。

```php
use huigan\EthSign;

$EthSign = new EthSign();
$sign="0xb319edba9d9d8c12a83d3a6e2a072fa5813dd8a5e9460ac3a475ab40a9988ddd059eed15f8c748a2b18c303b2a290a40c464b0a72274dfe1a96820bb02617b4f1b";
$msg="123456";
$address="0xc9fa719138a0d8fec944ed2bdc6d191e3ef08721";

$succ=$EthSign->verify($msg,$sign,$address);
```
