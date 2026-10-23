# 协议参数参考

完整参数见 [共识表](../protocol/parameters.md)。区块间隔为 30 秒；
Small m23 为 63 页 / 504 个输入 / 63 次调用，手动启用的 Large m24 为
206 / 504 / 63，自动 Native m24 为 63 / 504 / 63 并支持原生金融。各限制同时适用。

| 主题 | 参考 |
| --- | --- |
| 时间、窗口、State、传输限制 | [共识参数](../protocol/parameters.md) |
| 发行与手续费 | [网络经济](../protocol/economics.md) |
| ABI、程序及计数器 | [合约内核](../contracts/core.md) |
| 证明假设及准确计算 | [安全模型](../protocol/security-model.md) |
| 实际证明和验证成本 | [性能](performance.md) |

`paranoid_getContractProtocol` 返回已安装的合约限制和运行时状态。
迹字段为 GF(2^128)，宽挑战字段为 GF(2^256)，迹为一的挑战集合大小为 2^255。
C1 使用 65 个钱包查询及 133 个 History 查询。Poseidon2b 宽度为 4，S-box x^7，
8 个完整轮及 58 个部分轮。这些算法参数不是吞吐量保证。
