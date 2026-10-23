// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

pub(super) fn translate(source: &str) -> Option<(&'static str, &'static str)> {
    Some(match source {
        "FILTERS" => ("ФИЛЬТРЫ", "筛选"),
        "SAVED ACTIVITY" => ("СОХРАНЁННЫЕ ОПЕРАЦИИ", "已保存活动"),
        "MATCHING RECEIPTS" => ("НАЙДЕННЫЕ ЧЕКИ", "匹配收据"),
        "NO MATCHING RECEIPTS" => ("ПОДХОДЯЩИХ ЧЕКОВ НЕТ", "没有匹配的收据"),
        "Change the filters to see other saved receipts." => (
            "Измените фильтры, чтобы увидеть другие сохранённые чеки.",
            "更改筛选条件以查看其他已保存收据。",
        ),
        "Newest first" => ("Сначала новые", "最新优先"),
        "Oldest first" => ("Сначала старые", "最早优先"),
        "Asset" => ("Актив", "资产"),
        "Operation" => ("Операция", "操作"),
        "Any status" => ("Любой статус", "所有状态"),
        "Confirmed" => ("Подтверждённые", "已确认"),
        "Off chain" => ("Вне текущей цепи", "不在当前链中"),
        "Header unavailable" => ("Нет заголовка", "区块头不可用"),
        "Any operation" => ("Любая операция", "所有操作"),
        "Payment" => ("Платёж", "付款"),
        "Create token" => ("Создание токена", "创建代币"),
        "Send tokens" => ("Отправка токенов", "发送代币"),
        "Burn & redeem" => ("Сжигание и погашение", "销毁并赎回"),
        "Trade" => ("Сделка", "交易"),
        "Create NFT" => ("Создание NFT", "创建 NFT"),
        "Send NFT" => ("Отправка NFT", "发送 NFT"),
        "Burn NFT" => ("Сжигание NFT", "销毁 NFT"),
        "List NFT" => ("Выставить NFT", "上架 NFT"),
        "Buy NFT" => ("Покупка NFT", "购买 NFT"),
        "Cancel listing" => ("Отмена продажи", "取消上架"),
        "ASSET OR COLLECTION ID" => ("ID АКТИВА ИЛИ КОЛЛЕКЦИИ", "资产或集合 ID"),
        "OPERATION" => ("ОПЕРАЦИЯ", "操作"),
        "FROM · UTC" => ("С · UTC", "开始 · UTC"),
        "THROUGH · UTC" => ("ПО · UTC", "结束 · UTC"),
        "VERIFICATION" => ("ПРОВЕРКА", "验证"),
        "64 hex characters · optional" => (
            "64 шестнадцатеричных символа · необязательно",
            "64 个十六进制字符 · 可选",
        ),
        "Filter and sort the complete saved history." => (
            "Фильтры и сортировка всей сохранённой истории.",
            "筛选和排序全部已保存历史记录。",
        ),
        "Filters and sorting apply to the complete saved history before pagination." => (
            "Фильтры и сортировка применяются ко всей сохранённой истории до разбивки на страницы.",
            "先筛选和排序全部已保存历史记录，再分页显示。",
        ),
        "Use the complete 64-character asset or collection ID." => (
            "Укажите полный ID актива или коллекции из 64 символов.",
            "请输入完整的 64 字符资产或集合 ID。",
        ),
        "Use dates in YYYY-MM-DD format (UTC)." => (
            "Укажите даты в формате ГГГГ-ММ-ДД (UTC).",
            "请使用 YYYY-MM-DD 日期格式（UTC）。",
        ),
        "Enter a valid date from 1970 to 9999." => (
            "Укажите существующую дату с 1970 по 9999 год.",
            "请输入 1970 至 9999 年间的有效日期。",
        ),
        "The end date must be on or after the start date." => (
            "Конечная дата должна быть не раньше начальной.",
            "结束日期不能早于开始日期。",
        ),
        "Receipt filters require a v2.1.0 node." => (
            "Для фильтров чеков требуется нода v2.1.0.",
            "凭证筛选需要 v2.1.0 节点。",
        ),
        _ => return None,
    })
}
