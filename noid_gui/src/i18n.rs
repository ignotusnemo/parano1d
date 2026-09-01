// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use std::borrow::Cow;
use std::cell::Cell;

use iced::widget::{Text, TextInput};

use crate::model::Language;

thread_local! {
    static ACTIVE_LANGUAGE: Cell<Language> = const { Cell::new(Language::English) };
}

pub fn activate(language: Language) {
    ACTIVE_LANGUAGE.set(language);
}

pub fn active() -> Language {
    ACTIVE_LANGUAGE.get()
}

pub fn navigation_label(source: &'static str) -> &'static str {
    match (active(), source) {
        (Language::Russian, "Main") => "Главная",
        (Language::Russian, "Addresses") => "Адреса",
        (Language::Russian, "Send") => "Отправить",
        (Language::Russian, "Receipts") => "Чеки",
        (Language::Russian, "Mining") => "Майнинг",
        (Language::Russian, "Scope") => "Поиск",
        (Language::Russian, "Settings") => "Настройки",
        (Language::Russian, "Quit") => "Выход",
        (Language::Chinese, "Main") => "概览",
        (Language::Chinese, "Addresses") => "地址",
        (Language::Chinese, "Send") => "发送",
        (Language::Chinese, "Receipts") => "凭证",
        (Language::Chinese, "Mining") => "挖矿",
        (Language::Chinese, "Scope") => "查询",
        (Language::Chinese, "Settings") => "设置",
        (Language::Chinese, "Quit") => "退出",
        _ => source,
    }
}

pub fn address_label(label: &str) -> Cow<'_, str> {
    if label != "Main" {
        return Cow::Borrowed(label);
    }
    Cow::Borrowed(match active() {
        Language::English => "Main",
        Language::Russian => "Основной",
        Language::Chinese => "主地址",
    })
}

pub fn translate(source: &str) -> String {
    match active() {
        Language::English => source.to_owned(),
        language => translate_localized(language, source),
    }
}

pub fn text<'a>(content: impl ToString) -> Text<'a> {
    iced::widget::text(translate(&content.to_string()))
}

pub fn text_input<'a, Message>(placeholder: &str, value: &str) -> TextInput<'a, Message>
where
    Message: Clone,
{
    TextInput::new(&translate(placeholder), value)
}

fn translate_localized(language: Language, source: &str) -> String {
    if let Some((russian, chinese)) = exact_translation(source) {
        return match language {
            Language::English => source,
            Language::Russian => russian,
            Language::Chinese => chinese,
        }
        .to_owned();
    }

    if let Some(inner) = source
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    {
        let translated = translate_localized(language, inner);
        if translated != inner {
            return format!("[{translated}]");
        }
    }
    if let Some(inner) = source.strip_prefix('[') {
        if let Some((index, label)) = inner.split_once("] ") {
            let translated_label = translate_localized(language, label);
            if translated_label != label {
                return format!("[{index}] {translated_label}");
            }
        }
    }

    if let Some(value) = source.strip_prefix("BLOCK #") {
        if let Some((height, position)) = value.split_once(" · POSITION ") {
            return match language {
                Language::Russian => format!("БЛОК №{height} · ПОЗИЦИЯ {position}"),
                Language::Chinese => format!("区块 #{height} · 位置 {position}"),
                Language::English => source.to_owned(),
            };
        }
        return match language {
            Language::Russian => format!("БЛОК №{value}"),
            Language::Chinese => format!("区块 #{value}"),
            Language::English => source.to_owned(),
        };
    }
    if let Some(value) = source.strip_prefix("SLOT ") {
        return match language {
            Language::Russian => format!("СЛОТ {value}"),
            Language::Chinese => format!("槽位 {value}"),
            Language::English => source.to_owned(),
        };
    }
    if let Some(value) = source.strip_prefix("SEGMENT ") {
        return match language {
            Language::Russian => format!("СЕГМЕНТ {value}"),
            Language::Chinese => format!("分段 {value}"),
            Language::English => source.to_owned(),
        };
    }
    if let Some(value) = source.strip_prefix("PAGE ") {
        return match language {
            Language::Russian => format!("СТРАНИЦА {value}"),
            Language::Chinese => format!("第 {value} 页"),
            Language::English => source.to_owned(),
        };
    }
    if let Some(value) = source.strip_prefix("KEY ID  ") {
        return match language {
            Language::Russian => format!("ID КЛЮЧА  {value}"),
            Language::Chinese => format!("密钥 ID  {value}"),
            Language::English => source.to_owned(),
        };
    }
    if let Some(value) = source.strip_prefix("Address ") {
        if value.chars().all(|character| character.is_ascii_digit()) {
            return match language {
                Language::Russian => format!("Адрес {value}"),
                Language::Chinese => format!("地址 {value}"),
                Language::English => source.to_owned(),
            };
        }
    }
    if let Some(value) = source.strip_prefix("Automatic address discovery failed: ") {
        return match language {
            Language::Russian => format!("Не удалось автоматически найти адреса: {value}"),
            Language::Chinese => format!("自动发现地址失败：{value}"),
            Language::English => source.to_owned(),
        };
    }
    if let Some(value) = source.strip_prefix("Prepare secret photo: ") {
        return match language {
            Language::Russian => format!("Не удалось подготовить секретное фото: {value}"),
            Language::Chinese => format!("无法处理密钥照片：{value}"),
            Language::English => source.to_owned(),
        };
    }
    if let Some(value) = source.strip_prefix("SCANNING PIXELS · ") {
        return match language {
            Language::Russian => format!("АНАЛИЗ ПИКСЕЛЕЙ · {value}"),
            Language::Chinese => format!("正在分析像素 · {value}"),
            Language::English => source.to_owned(),
        };
    }
    if let Some(value) = source
        .strip_prefix("LATEST ")
        .and_then(|value| value.strip_suffix(" LINES"))
    {
        return match language {
            Language::Russian => format!("ПОСЛЕДНИЕ {value} СТРОК"),
            Language::Chinese => format!("最近 {value} 行"),
            Language::English => source.to_owned(),
        };
    }
    if let Some(value) = source.strip_prefix("TO ") {
        return match language {
            Language::Russian => format!("КОМУ {value}"),
            Language::Chinese => format!("收款方 {value}"),
            Language::English => source.to_owned(),
        };
    }
    if let Some(value) = source.strip_suffix(" OUTPUTS") {
        return match language {
            Language::Russian => format!(
                "{value} {}",
                russian_noun(value, "ВЫХОД", "ВЫХОДА", "ВЫХОДОВ")
            ),
            Language::Chinese => format!("{value} 个输出"),
            Language::English => source.to_owned(),
        };
    }
    if let Some(value) = source.strip_prefix("EDIT ADDRESS ") {
        return match language {
            Language::Russian => format!("ИЗМЕНИТЬ АДРЕС {value}"),
            Language::Chinese => format!("编辑地址 {value}"),
            Language::English => source.to_owned(),
        };
    }
    if let Some(value) = source.strip_prefix("SEND · ") {
        return match language {
            Language::Russian => format!("ОТПРАВИТЬ · {value}"),
            Language::Chinese => format!("发送 · {value}"),
            Language::English => source.to_owned(),
        };
    }
    if let Some(value) = source.strip_prefix("CONSOLIDATE · ") {
        return match language {
            Language::Russian => format!("ОБЪЕДИНИТЬ · {value}"),
            Language::Chinese => format!("整合 · {value}"),
            Language::English => source.to_owned(),
        };
    }
    if let Some(value) = source.strip_prefix("ORIGIN ") {
        return match language {
            Language::Russian => format!("ИСТОЧНИК {value}"),
            Language::Chinese => format!("来源 {value}"),
            Language::English => source.to_owned(),
        };
    }
    if let Some(value) = source.strip_prefix("OUT #") {
        return match language {
            Language::Russian => format!("ВЫХОД #{value}"),
            Language::Chinese => format!("输出 #{value}"),
            Language::English => source.to_owned(),
        };
    }
    if let Some(value) = source
        .strip_prefix("FULL DATA #")
        .filter(|value| value.contains('–'))
    {
        return match language {
            Language::Russian => format!("ПОЛНЫЕ ДАННЫЕ №{value}"),
            Language::Chinese => format!("完整数据 #{value}"),
            Language::English => source.to_owned(),
        };
    }
    if let Some(value) = source
        .strip_prefix("m")
        .and_then(|value| value.strip_suffix(" conf"))
        .filter(|value| value.contains(" · "))
    {
        return match language {
            Language::Russian => format!("m{value} подтв."),
            Language::Chinese => format!("m{value} 次确认"),
            Language::English => source.to_owned(),
        };
    }
    if let Some(value) = source.strip_suffix(" NOID selected") {
        return match language {
            Language::Russian => format!("ВЫБРАНО {value} NOID"),
            Language::Chinese => format!("已选择 {value} NOID"),
            Language::English => source.to_owned(),
        };
    }
    if let Some(value) = source.strip_suffix(" · CHANGE") {
        return match language {
            Language::Russian => format!("{value} · СДАЧА"),
            Language::Chinese => format!("{value} · 找零"),
            Language::English => source.to_owned(),
        };
    }
    if let Some(value) = source.strip_suffix(" · METADATA IGNORED") {
        return match language {
            Language::Russian => format!("{value} · МЕТАДАННЫЕ НЕ УЧИТЫВАЮТСЯ"),
            Language::Chinese => format!("{value} · 忽略元数据"),
            Language::English => source.to_owned(),
        };
    }
    if let Some(value) = source.strip_suffix(" ① spendable") {
        return match language {
            Language::Russian => format!("{value} ① доступно"),
            Language::Chinese => format!("{value} ① 可用"),
            Language::English => source.to_owned(),
        };
    }
    if source.starts_with("B25 ") && source.contains(" · B255 ") {
        let mut parts = source.splitn(2, " · B255 ");
        let b25 = parts.next().unwrap_or_default().trim_start_matches("B25 ");
        let b255 = parts.next().unwrap_or_default();
        return format!(
            "B25 {} · B255 {}",
            translate_localized(language, b25),
            translate_localized(language, b255)
        );
    }
    if let Some(value) = source
        .strip_prefix("[BLOCK #")
        .and_then(|value| value.strip_suffix(']'))
    {
        if let Some((height, position)) = value.split_once(" · POSITION ") {
            return match language {
                Language::Russian => format!("[БЛОК №{height} · ПОЗИЦИЯ {position}]"),
                Language::Chinese => format!("[区块 #{height} · 位置 {position}]"),
                Language::English => source.to_owned(),
            };
        }
    }
    if let Some(value) = source.strip_prefix("KEY #") {
        if let Some((key, rest)) = value.split_once(" · I/O ") {
            return match language {
                Language::Russian => format!("КЛЮЧ №{key} · ВХ/ВЫХ {rest}"),
                Language::Chinese => format!("密钥 #{key} · 输入/输出 {rest}"),
                Language::English => source.to_owned(),
            };
        }
    }
    if let Some((inputs, rest)) = source.split_once(" in · ") {
        if let Some((outputs, fee)) = rest.split_once(" out · fee ") {
            return match language {
                Language::Russian => {
                    format!("{inputs} вх. · {outputs} вых. · комиссия {fee}")
                }
                Language::Chinese => format!("{inputs} 输入 · {outputs} 输出 · 手续费 {fee}"),
                Language::English => source.to_owned(),
            };
        }
    }
    if let Some((selected, rest)) = source.split_once(" smallest of ") {
        if let Some((total, value)) = rest.split_once(" · ") {
            return match language {
                Language::Russian => format!("{selected} наименьших из {total} · {value}"),
                Language::Chinese => format!("从 {total} 个中选择最小的 {selected} 个 · {value}"),
                Language::English => source.to_owned(),
            };
        }
    }
    if let Some((before, rest)) = source.split_once(" → ") {
        if let Some((remaining, freed)) = rest
            .strip_suffix(" slots freed")
            .and_then(|value| value.split_once(" outputs · "))
        {
            return match language {
                Language::Russian => {
                    format!("{before} → {remaining} выходов · освобождено слотов: {freed}")
                }
                Language::Chinese => {
                    format!("{before} → {remaining} 个输出 · 释放 {freed} 个槽位")
                }
                Language::English => source.to_owned(),
            };
        }
    }
    if let Some(value) =
        source.strip_suffix(" paid to the block miner. Coinbase has no spend inputs.")
    {
        return match language {
            Language::Russian => {
                format!("{value} начислено майнеру блока. У coinbase нет расходуемых входов.")
            }
            Language::Chinese => {
                format!("{value} 已发放给该区块的矿工。Coinbase 没有可花费输入。")
            }
            Language::English => source.to_owned(),
        };
    }
    if let Some(value) = source.strip_suffix(" remains untouched.") {
        if let Some(count) = value.split_whitespace().next() {
            return match language {
                Language::Russian => format!(
                    "{count} {} останется без изменений.",
                    russian_noun(count, "выход", "выхода", "выходов")
                ),
                Language::Chinese => format!("另有 {count} 个输出保持不变。"),
                Language::English => source.to_owned(),
            };
        }
    }
    if let Some(value) = source.strip_suffix(" remain untouched.") {
        if let Some(count) = value.split_whitespace().next() {
            return match language {
                Language::Russian => format!(
                    "{count} {} останутся без изменений.",
                    russian_noun(count, "выход", "выхода", "выходов")
                ),
                Language::Chinese => format!("另有 {count} 个输出保持不变。"),
                Language::English => source.to_owned(),
            };
        }
    }
    if let Some((label, status)) = source.rsplit_once(" [") {
        if let Some(status) = status.strip_suffix(']') {
            let translated_label = translate_localized(language, label);
            let translated_status = translate_localized(language, status);
            if translated_label != label || translated_status != status {
                return format!("{translated_label} [{translated_status}]");
            }
        }
    }
    if let Some(value) = source.strip_suffix(" TRANSACTION") {
        let kind = translate_localized(language, value);
        return match language {
            Language::Russian => format!("ТРАНЗАКЦИЯ · {kind}"),
            Language::Chinese => format!("{kind}交易"),
            Language::English => source.to_owned(),
        };
    }
    if let Some((value, unit)) = compact_age(source) {
        return match language {
            Language::Russian => {
                let unit = match unit {
                    "s" => "с",
                    "m" => "мин",
                    "h" => "ч",
                    "d" => "дн",
                    _ => unit,
                };
                format!("{value} {unit} назад")
            }
            Language::Chinese => {
                let unit = match unit {
                    "s" => "秒",
                    "m" => "分钟",
                    "h" => "小时",
                    "d" => "天",
                    _ => unit,
                };
                format!("{value} {unit}前")
            }
            Language::English => source.to_owned(),
        };
    }

    source.to_owned()
}

fn compact_age(source: &str) -> Option<(&str, &str)> {
    let value = source.strip_suffix(" ago")?;
    for unit in ["s", "m", "h", "d"] {
        if let Some(number) = value.strip_suffix(unit) {
            if !number.is_empty() && number.chars().all(|character| character.is_ascii_digit()) {
                return Some((number, unit));
            }
        }
    }
    None
}

fn russian_noun<'a>(count: &str, one: &'a str, few: &'a str, many: &'a str) -> &'a str {
    let Ok(count) = count.replace(' ', "").parse::<u64>() else {
        return many;
    };
    let last_two = count % 100;
    if (11..=14).contains(&last_two) {
        many
    } else {
        match count % 10 {
            1 => one,
            2..=4 => few,
            _ => many,
        }
    }
}

fn exact_translation(source: &str) -> Option<(&'static str, &'static str)> {
    Some(match source {
        // Application shell and lifecycle.
        "STARTING" => ("ЗАПУСК", "正在启动"),
        "OFFLINE" => ("НЕ В СЕТИ", "离线"),
        "PREVIEW" => ("ПРЕДПРОСМОТР", "预览"),
        "SYNCED" => ("ОНЛАЙН", "已同步"),
        "SYNCING" => ("СИНХРОНИЗАЦИЯ", "正在同步"),
        "SYNCING HEADERS" => ("СИНХРОНИЗАЦИЯ ЗАГОЛОВКОВ", "正在同步区块头"),
        "SYNCING STATE" => ("СИНХРОНИЗАЦИЯ STATE", "正在同步状态"),
        "SWITCHING" => ("ПЕРЕКЛЮЧЕНИЕ", "正在切换"),
        "ISOLATED" => ("ИЗОЛИРОВАН", "隔离运行"),
        "MINING ON" => ("МАЙНИНГ ВКЛ.", "挖矿已开启"),
        "MINING OFF" => ("МАЙНИНГ ВЫКЛ.", "挖矿已关闭"),
        "PEERS" => ("ПИРЫ", "节点"),
        "HEIGHT" => ("ВЫСОТА", "高度"),
        "BACKEND" => ("БЭКЕНД", "计算后端"),
        "CLOSING WALLET SAFELY" => ("БЕЗОПАСНОЕ ЗАКРЫТИЕ КОШЕЛЬКА", "正在安全关闭钱包"),
        "FINISHING THE CURRENT PROOF STEP" => (
            "ЗАВЕРШАЕМ ТЕКУЩИЙ ЭТАП ДОКАЗАТЕЛЬСТВА",
            "正在完成当前证明步骤",
        ),
        "THE WALLET WILL CLOSE AUTOMATICALLY" => (
            "КОШЕЛЁК ЗАКРОЕТСЯ АВТОМАТИЧЕСКИ",
            "完成后钱包将自动关闭",
        ),

        // First run and secret handling.
        "FIRST RUN" => ("ПЕРВЫЙ ЗАПУСК", "首次启动"),
        "MASTER KEY SETUP" => ("НАСТРОЙКА МАСТЕР-КЛЮЧА", "设置主密钥"),
        "ONE SECRET · EVERY ADDRESS" => ("ОДИН СЕКРЕТ · ВСЕ АДРЕСА", "一个密钥 · 所有地址"),
        "THE KEY IS STORED LOCALLY" => ("КЛЮЧ ХРАНИТСЯ ЛОКАЛЬНО", "密钥仅存储在本机"),
        "INITIALIZE OWNER" => ("НАСТРОЙКА КОШЕЛЬКА", "初始化钱包"),
        "Choose how this device obtains the master key." => (
            "Выберите, как получить мастер-ключ на этом устройстве.",
            "选择此设备获取主密钥的方式。",
        ),
        "ADDRESSES" => ("АДРЕСА", "地址"),
        "256-BIT KEY" => ("256-БИТНЫЙ КЛЮЧ", "256 位密钥"),
        "No keypair. No signature." => ("Без пары ключей. Без подписи.", "无需密钥对，无需签名。"),
        "Quantum\u{2011}resistant." => ("Квантово-устойчиво.", "抗量子攻击。"),
        "No keypair. No signature. Quantum\u{2011}resistant." => (
            "Без пары ключей. Без подписи. Квантово-устойчиво.",
            "无需密钥对，无需签名，抗量子攻击。",
        ),
        "A secret is enough." => ("Достаточно одного секрета.", "一个密钥就够了。"),
        "GENERATE" => ("СОЗДАТЬ", "新建"),
        "IMPORT" => ("ИМПОРТ", "导入"),
        "USE PHOTO" => ("ПО ФОТО", "使用照片"),
        "Create a new 256-bit key" => ("Создать новый 256-битный ключ", "创建新的 256 位密钥"),
        "Restore from existing key" => ("Восстановить из существующего ключа", "使用现有密钥恢复"),
        "Derive the 256-bit key from pixels" => (
            "Получить 256-битный ключ из пикселей",
            "从像素生成 256 位密钥",
        ),
        "RANDOM KEY" => ("СЛУЧАЙНЫЙ КЛЮЧ", "随机密钥"),
        "A cryptographically random key will be created and stored in the local keystore." => (
            "Криптографически случайный ключ будет создан и сохранён в локальном хранилище.",
            "将生成安全的随机密钥，并保存在本机密钥库中。",
        ),
        "CREATE WALLET" => ("СОЗДАТЬ КОШЕЛЁК", "创建钱包"),
        "CREATING WALLET…" | "CREATING..." => ("СОЗДАНИЕ КОШЕЛЬКА…", "正在创建钱包…"),
        "64 HEX CHARACTERS" => ("64 ШЕСТНАДЦАТЕРИЧНЫХ СИМВОЛА", "64 位十六进制字符"),
        "The key restores the same deterministic address sequence." => (
            "Ключ восстанавливает ту же последовательность адресов.",
            "此密钥可恢复完全相同的确定性地址序列。",
        ),
        "Paste 64-character key" => ("Вставьте ключ из 64 символов", "粘贴 64 位字符的密钥"),
        "RESTORE WALLET" => ("ВОССТАНОВИТЬ КОШЕЛЁК", "恢复钱包"),
        "RESTORING WALLET…" => ("ВОССТАНОВЛЕНИЕ КОШЕЛЬКА…", "正在恢复钱包…"),
        "PRIVATE PHOTO" => ("ЛИЧНОЕ ФОТО", "私密照片"),
        "PIXELS → 256-BIT KEY" => ("ПИКСЕЛИ → 256-БИТНЫЙ КЛЮЧ", "像素 → 256 位密钥"),
        "The key is derived from decoded pixels. Metadata and the file name are ignored." => (
            "Ключ создаётся из декодированных пикселей. Метаданные и имя файла не учитываются.",
            "密钥由解码后的像素生成，文件名和元数据不会参与计算。",
        ),
        "Messaging apps may compress the image and change the key. Send the photo as a file." => (
            "Мессенджеры могут сжать изображение и изменить ключ. Передавайте фото как файл.",
            "聊天软件可能会压缩图片并改变密钥。请以文件形式发送照片。",
        ),
        "CHOOSE PHOTO" => ("ВЫБРАТЬ ФОТО", "选择照片"),
        "READING PHOTO…" => ("ЧТЕНИЕ ФОТО…", "正在读取照片…"),
        "USE THIS PHOTO" => ("ИСПОЛЬЗОВАТЬ ЭТО ФОТО", "使用这张照片"),
        "IMPORTING WALLET…" => ("ИМПОРТ КОШЕЛЬКА…", "正在导入钱包…"),
        "← ESC BACK" => ("← ESC НАЗАД", "← ESC 返回"),
        "PHOTO SELECTED" => ("ФОТО ВЫБРАНО", "已选择照片"),
        "PHOTO KEY READY" => ("КЛЮЧ ИЗ ФОТО ГОТОВ", "照片密钥已就绪"),
        "PHOTO KEY ACTIVE" => ("КЛЮЧ ИЗ ФОТО АКТИВЕН", "照片密钥已启用"),
        "PHOTO KEY" => ("КЛЮЧ ИЗ ФОТО", "照片密钥"),
        "PHOTO LOCKED FOR SCAN" => ("ФОТО ЗАБЛОКИРОВАНО НА ВРЕМЯ АНАЛИЗА", "正在分析照片"),
        "SCANNING PIXELS…" => ("АНАЛИЗ ПИКСЕЛЕЙ…", "正在分析像素…"),
        "KEY READY" => ("КЛЮЧ ГОТОВ", "密钥已就绪"),
        "KEY READY · 100%" => ("КЛЮЧ ГОТОВ · 100%", "密钥已就绪 · 100%"),
        "PREVIEW NOT STORED" => ("ПРЕДПРОСМОТР НЕ СОХРАНЯЕТСЯ", "预览图不会保存"),
        "METADATA IGNORED" => ("МЕТАДАННЫЕ НЕ УЧИТЫВАЮТСЯ", "忽略元数据"),

        // Shared actions and states.
        "ACTIONS" => ("ДЕЙСТВИЯ", "操作"),
        "ACTIVE" => ("АКТИВЕН", "当前"),
        "ALL" => ("ВСЕ", "全部"),
        "APPLY & RESTART" => ("ПРИМЕНИТЬ И ПЕРЕЗАПУСТИТЬ", "应用并重启"),
        "APPLYING…" => ("ПРИМЕНЕНИЕ…", "正在应用…"),
        "AVAILABLE" => ("ДОСТУПНО", "可用"),
        "BUILDING" => ("ПОСТРОЕНИЕ", "正在构建"),
        "BUILDING PROOF…" => ("ПОСТРОЕНИЕ ДОКАЗАТЕЛЬСТВА…", "正在构建证明…"),
        "CALCULATING TRANSACTION" => ("РАСЧЁТ ТРАНЗАКЦИИ", "正在计算交易"),
        "CANCEL" => ("ОТМЕНА", "取消"),
        "CHOOSE" => ("ВЫБРАТЬ", "选择"),
        "CLEAR" => ("ОЧИСТИТЬ", "清除"),
        "CLOSE" => ("ЗАКРЫТЬ", "关闭"),
        "COPIED" => ("СКОПИРОВАНО", "已复制"),
        "COPIED ✓" => ("СКОПИРОВАНО ✓", "已复制 ✓"),
        "CONFIRMED" => ("ПОДТВЕРЖДЕНО", "已确认"),
        "DETAILS" => ("ДЕТАЛИ", "详情"),
        "DETAILS →" => ("ДЕТАЛИ →", "详情 →"),
        "Address" => ("Адрес", "地址"),
        "15 s" => ("15 с", "15 秒"),
        "EDIT" => ("ИЗМЕНИТЬ", "编辑"),
        "EMPTY" => ("ПУСТО", "空"),
        "ESC CANCEL" => ("ESC ОТМЕНА", "ESC 取消"),
        "ESC CLEAR" => ("ESC ОЧИСТИТЬ", "ESC 清除"),
        "ESC CLOSE" => ("ESC ЗАКРЫТЬ", "ESC 关闭"),
        "GENERATED" => ("СОЗДАН", "已生成"),
        "GENERATING & RESTARTING…" => ("СОЗДАНИЕ И ПЕРЕЗАПУСК…", "正在生成并重启…"),
        "IN" => ("ВХОД", "输入"),
        "INCOMING" => ("ВХОДЯЩИЕ", "待入账"),
        "IMPORTANT" => ("ВАЖНО", "重要"),
        "LIVE" => ("АКТУАЛЬНО", "实时"),
        "LOCAL" => ("ЛОКАЛЬНО", "本地"),
        "NEXT →" => ("ДАЛЕЕ →", "下一页 →"),
        "NO" => ("НЕТ", "否"),
        "OK" => ("ДА", "是"),
        "OPEN" => ("ОТКРЫТЬ", "打开"),
        "OUT" => ("ВЫХОД", "输出"),
        "PASTE" => ("ВСТАВИТЬ", "粘贴"),
        "PENDING" => ("ОЖИДАЕТ", "待处理"),
        "PREPARING" => ("ПОДГОТОВКА", "准备中"),
        "FAILED" => ("ОШИБКА", "失败"),
        "READING…" => ("ЧТЕНИЕ…", "正在读取…"),
        "RECEIVED" => ("ПОЛУЧЕНО", "已接收"),
        "READY" => ("ГОТОВО", "就绪"),
        "REFRESH" => ("ОБНОВИТЬ", "刷新"),
        "REFRESHING…" => ("ОБНОВЛЕНИЕ…", "正在刷新…"),
        "RESET" => ("СБРОСИТЬ", "重置"),
        "RESTARTING…" => ("ПЕРЕЗАПУСК…", "正在重启…"),
        "RESTARTING NODE" => ("ПЕРЕЗАПУСК УЗЛА", "正在重启节点"),
        "RESUME" => ("ПРОДОЛЖИТЬ", "继续"),
        "RETRY" => ("ПОВТОРИТЬ", "重试"),
        "SAVE" => ("СОХРАНИТЬ", "保存"),
        "SEARCH" => ("НАЙТИ", "搜索"),
        "SEARCHING…" => ("ПОИСК…", "正在搜索…"),
        "SHOWN" => ("ПОКАЗАНО", "已显示"),
        "SPEND" => ("ПОТРАТИТЬ", "花费"),
        "SPENDING SECRET" => ("СЕКРЕТ ТРАТЫ", "支出密钥"),
        "SPENDABLE" => ("ДОСТУПНО", "可用"),
        "SPENT" => ("ПОТРАЧЕНО", "已花费"),
        "STATUS" => ("СТАТУС", "状态"),
        "STOPPED" => ("ОСТАНОВЛЕН", "已停止"),
        "TRY AGAIN" => ("ПОВТОРИТЬ", "重试"),
        "UNVERIFIED" => ("НЕ ПРОВЕРЕНО", "未验证"),
        "USE" => ("ИСПОЛЬЗОВАТЬ", "使用"),
        "USING..." => ("ПРИМЕНЕНИЕ…", "正在使用…"),
        "VERIFIED" => ("ПРОВЕРЕНО", "已验证"),
        "VIEW" => ("ОТКРЫТЬ", "查看"),
        "WAIT" => ("ОЖИДАНИЕ", "请稍候"),
        "WORKING…" => ("ВЫПОЛНЕНИЕ…", "处理中…"),
        "← PREV" => ("← НАЗАД", "← 上一页"),

        // Main wallet view and addresses.
        "STATE LVL" => ("УРОВЕНЬ", "状态层级"),
        "STATE USE" => ("ЗАНЯТО", "状态占用"),
        "MEMPOOL" => ("МЕМПУЛ", "内存池"),
        "CPU" => ("CPU", "CPU"),
        "MEMORY" => ("ПАМЯТЬ", "内存"),
        "MINING TH" => ("ПОТОКИ", "挖矿线程"),
        "DIFFICULTY" => ("СЛОЖНОСТЬ", "难度"),
        "ACTIVE ADDRESS" => ("АКТИВНЫЙ АДРЕС", "当前地址"),
        "SWITCH" => ("СМЕНИТЬ", "切换"),
        "NOID BALANCE" => ("БАЛАНС NOID", "NOID 余额"),
        "SPENDABLE OUTPUTS" => ("ДОСТУПНЫЕ ВЫХОДЫ", "可用输出"),
        "CONSOLIDATE" => ("ОБЪЕДИНИТЬ", "整合"),
        "CONSOLIDATION RECOMMENDED" => ("РЕКОМЕНДУЕТСЯ ОБЪЕДИНЕНИЕ", "建议整合 UTXO"),
        "Please consolidate up to 64 UTXOs into one state slot to support the network and speed up wallet operations." => (
            "Объедините до 64 UTXO в один слот состояния: это помогает сети и ускоряет работу кошелька.",
            "请将最多 64 个 UTXO 整合到一个状态槽位中，以减轻网络负担并提升钱包速度。",
        ),
        "MY UTXO SET" => ("МОИ UTXO", "我的 UTXO"),
        "MY UTXOS" => ("МОИ UTXO", "我的 UTXO"),
        "LIVE UTXOS" => ("ТЕКУЩИЕ UTXO", "实时 UTXO"),
        "LIVE SLOTS" => ("ЗАНЯТЫЕ СЛОТЫ", "实时槽位"),
        "SEGMENT" => ("СЕГМЕНТ", "分段"),
        "SLOT" => ("СЛОТ", "槽位"),
        "VALUE / NOID" => ("СУММА / NOID", "金额 / NOID"),
        "ORIGIN" => ("ИСТОЧНИК", "来源"),
        "SELECTED OUTPUT" => ("ВЫБРАННЫЙ ВЫХОД", "已选输出"),
        "FILTER ACTIVE" => ("ФИЛЬТР ВКЛЮЧЁН", "筛选已启用"),
        "NETWORK" => ("СЕТЬ", "网络"),
        "STATE MAP READY" => ("КАРТА СОСТОЯНИЯ ГОТОВА", "状态图已就绪"),
        "STATE DENSITY" => ("ПЛОТНОСТЬ СОСТОЯНИЯ", "状态密度"),
        "STATE SLOT" => ("СЛОТ СОСТОЯНИЯ", "状态槽位"),
        "SELECT A MAGENTA SEGMENT" => ("ВЫБЕРИТЕ СИРЕНЕВЫЙ СЕГМЕНТ", "选择洋红色分段"),
        "LIVE STATE" => ("ТЕКУЩЕЕ СОСТОЯНИЕ", "实时状态"),
        "ROOT" => ("КОРЕНЬ", "根"),
        "ADDRESS BOOK" => ("АДРЕСНАЯ КНИГА", "地址簿"),
        "NEW ADDRESS" => ("НОВЫЙ АДРЕС", "新建地址"),
        "LABEL" => ("МЕТКА", "标签"),
        "LABELS ARE LOCAL · ADDRESSES CANNOT BE DELETED" => (
            "МЕТКИ ХРАНЯТСЯ ЛОКАЛЬНО · АДРЕСА НЕЛЬЗЯ УДАЛИТЬ",
            "标签仅保存在本机 · 地址无法删除",
        ),
        "LOCAL LABEL" => ("ЛОКАЛЬНАЯ МЕТКА", "本地标签"),
        "Address label" => ("Метка адреса", "地址标签"),
        "The label is stored only on this device." => (
            "Метка хранится только на этом устройстве.",
            "标签仅保存在此设备上。",
        ),
        "FORGING THE PROOF" => ("КУЁМ ДОКАЗАТЕЛЬСТВО", "正在锻造证明"),
        "LOCAL PROOF CONSTRUCTION" => ("ЛОКАЛЬНОЕ ПОСТРОЕНИЕ ДОКАЗАТЕЛЬСТВА", "本地构建证明"),
        "TRANSACTION NOT SENT" => ("ТРАНЗАКЦИЯ НЕ ОТПРАВЛЕНА", "交易未发送"),
        "Calculated from the current wallet state. Your secret stays on this device." => (
            "Расчёт основан на текущем состоянии кошелька. Секрет не покидает устройство.",
            "根据钱包当前状态计算；密钥始终留在此设备上。",
        ),
        "Checking available outputs and the network fee…" => (
            "Проверяем доступные выходы и комиссию сети…",
            "正在检查可用输出和网络手续费…",
        ),
        "The wallet could not calculate the transaction." => (
            "Кошелёк не смог рассчитать транзакцию.",
            "钱包无法计算这笔交易。",
        ),
        "PROVE & SEND" => ("ПОСТРОИТЬ И ОТПРАВИТЬ", "生成证明并发送"),
        "RECIPIENT" => ("ПОЛУЧАТЕЛЬ", "收款地址"),
        "Paste an o1 address" => ("Вставьте адрес o1", "粘贴 o1 地址"),
        "AMOUNT / NOID" => ("СУММА / NOID", "金额 / NOID"),
        "AUTOMATIC · calculated by the wallet" => (
            "АВТОМАТИЧЕСКИ · РАССЧИТАНО КОШЕЛЬКОМ",
            "自动 · 由钱包计算",
        ),
        "Your secret stays on this device. Only the transaction is sent." => (
            "Секрет остаётся на устройстве. В сеть отправляется только транзакция.",
            "密钥始终留在此设备上，只有交易会发送到网络。",
        ),
        "TRANSACTION SENT" => ("ТРАНЗАКЦИЯ ОТПРАВЛЕНА", "交易已发送"),
        "SEND ANOTHER" => ("ОТПРАВИТЬ ЕЩЁ", "继续发送"),
        "CONSOLIDATION SENT" => ("ОБЪЕДИНЕНИЕ ОТПРАВЛЕНО", "整合交易已发送"),
        "CANNOT CONSOLIDATE" => ("НЕ УДАЁТСЯ ОБЪЕДИНИТЬ", "无法整合"),
        "PROVE & CONSOLIDATE" => ("ПОСТРОИТЬ И ОБЪЕДИНИТЬ", "生成证明并整合"),
        "INPUT VALUE" => ("СУММА ВХОДОВ", "输入金额"),
        "NETWORK FEE" => ("КОМИССИЯ СЕТИ", "网络手续费"),
        "NEW OUTPUT" => ("НОВЫЙ ВЫХОД", "新输出"),
        "TOTAL BALANCE" => ("ОБЩИЙ БАЛАНС", "总余额"),
        "Only the network fee changes the balance." => (
            "Баланс изменится только на комиссию сети.",
            "余额只会扣除网络手续费。",
        ),
        "FREED" => ("ОСВОБОЖДЕНО", "释放槽位"),
        "INPUTS" => ("ВХОДЫ", "输入"),
        "OUTPUTS" => ("ВЫХОДЫ", "输出"),
        "FEE" => ("КОМИССИЯ", "手续费"),
        "TXID" => ("TXID", "TXID"),
        "TO" => ("КОМУ", "收款方"),
        "AMOUNT" => ("СУММА", "金额"),

        // Receipts and verification.
        "MINE" => ("МОИ", "我的凭证"),
        "MY RECEIPTS" => ("МОИ ЧЕКИ", "我的凭证"),
        "VERIFY" => ("ПРОВЕРИТЬ", "验证"),
        "SAVED RECEIPTS" => ("СОХРАНЁННЫЕ ЧЕКИ", "已保存凭证"),
        "THE BLOCK BODY MAY EXPIRE. THE RECEIPT DOES NOT." => (
            "ТЕЛО БЛОКА МОЖЕТ ИСЧЕЗНУТЬ. ЧЕК ОСТАНЕТСЯ.",
            "区块正文会过期，支付凭证不会。",
        ),
        "Saved locally at confirmation, a receipt proves the exact payment and its inclusion in a canonical block. Key import on another device does not restore receipts." => (
            "Чек сохраняется локально после подтверждения и доказывает точный платёж и его включение в канонический блок. Импорт ключа на другом устройстве чеки не восстановит.",
            "交易确认后，支付凭证会保存在本机，用于证明付款详情及其已写入规范链。仅在另一台设备上导入密钥，无法恢复这些凭证。",
        ),
        "NO PAYMENT RECEIPTS YET" => ("ПОКА НЕТ ЧЕКОВ ОБ ОПЛАТЕ", "暂无支付凭证"),
        "A receipt appears automatically when one of your sent transactions is confirmed." => (
            "Чек появится автоматически после подтверждения отправленной транзакции.",
            "您发送的交易确认后，支付凭证会自动出现。",
        ),
        "SENT TRANSACTIONS" => ("ОТПРАВЛЕННЫЕ ТРАНЗАКЦИИ", "已发送交易"),
        "SELECT A PAYMENT RECEIPT" => ("ВЫБЕРИТЕ ЧЕК ОБ ОПЛАТЕ", "选择支付凭证"),
        "SELECTED RECEIPT" => ("ВЫБРАННЫЙ ЧЕК", "已选凭证"),
        "COPY RECEIPT" => ("СКОПИРОВАТЬ ЧЕК", "复制凭证"),
        "Paste receipt hex" => ("Вставьте чек в hex-формате", "粘贴十六进制凭证"),
        "VERIFY A PAYMENT" => ("ПРОВЕРИТЬ ПЛАТЁЖ", "验证付款"),
        "WHITESPACE IS IGNORED" => ("ПРОБЕЛЫ НЕ УЧИТЫВАЮТСЯ", "自动忽略空白字符"),
        "Verification checks the receipt against the network's canonical headers. The receipt stays local." => (
            "Чек проверяется по каноническим заголовкам сети и остаётся на устройстве.",
            "验证会将凭证与网络的规范区块头核对；凭证始终留在本机。",
        ),
        "PASTE · VERIFY · KNOW" => ("ВСТАВЬТЕ · ПРОВЕРЬТЕ · УБЕДИТЕСЬ", "粘贴 · 验证 · 确认"),
        "The result authenticates the transaction, outputs, fee, block position and canonical-chain membership." => (
            "Результат подтверждает подлинность транзакции, выходов, комиссии, позиции в блоке и принадлежности канонической цепочке.",
            "验证结果会确认交易、输出、手续费、区块位置以及其规范链归属。",
        ),
        "CHECKING RECEIPT AND CANONICAL HEADER" => (
            "ПРОВЕРКА ЧЕКА И КАНОНИЧЕСКОГО ЗАГОЛОВКА",
            "正在核验凭证与规范区块头",
        ),
        "VERIFYING…" => ("ПРОВЕРКА…", "正在验证…"),
        "VALID · CANONICAL" => ("ДЕЙСТВИТЕЛЕН · В КАНОНИЧЕСКОЙ ЦЕПОЧКЕ", "有效 · 位于规范链"),
        "RECEIPT VALID · NOT CANONICAL" => (
            "ЧЕК ДЕЙСТВИТЕЛЕН · БЛОК НЕ В КАНОНИЧЕСКОЙ ЦЕПОЧКЕ",
            "凭证有效 · 区块不在规范链",
        ),
        "INVALID RECEIPT" => ("НЕДЕЙСТВИТЕЛЬНЫЙ ЧЕК", "凭证无效"),
        "No payment fields are trusted because the Merkle proof did not verify." => (
            "Данным платежа нельзя доверять: доказательство Merkle не прошло проверку.",
            "Merkle 证明未通过验证，因此不能信任任何付款字段。",
        ),
        "AUTHENTICATED PAYMENT" => ("ПОДТВЕРЖДЁННЫЙ ПЛАТЁЖ", "已验证付款"),
        "INPUT OWNERSHIP" => ("ВЛАДЕЛЬЦЫ ВХОДОВ", "输入所有权"),
        "AUTHENTICATED OUTPUTS" => ("ПОДТВЕРЖДЁННЫЕ ВЫХОДЫ", "已验证输出"),
        "RECEIPT ERROR" => ("ОШИБКА ЧЕКА", "凭证错误"),
        "READING PAYMENT RECEIPTS" => ("ЧТЕНИЕ ЧЕКОВ", "正在读取支付凭证"),
        "VERIFYING SELECTED RECEIPT" => ("ПРОВЕРКА ВЫБРАННОГО ЧЕКА", "正在验证所选凭证"),

        // Scope.
        "ADDRESS · BLOCK HEIGHT/HASH · TXID · SLOT:<NUMBER>" => (
            "АДРЕС · ВЫСОТА/ХЕШ БЛОКА · TXID · SLOT:<НОМЕР>",
            "地址 · 区块高度/哈希 · TXID · SLOT:<编号>",
        ),
        "Search live state. Full block data is retained for 18 blocks; receipts prove older payments." => (
            "Поиск по текущему состоянию. Полные данные хранятся 18 блоков; более старые платежи доказываются чеками.",
            "查询实时状态。完整区块数据保留 18 个区块；更早的付款可由支付凭证证明。",
        ),
        "READING CANONICAL STATE" => ("ЧТЕНИЕ КАНОНИЧЕСКОГО СОСТОЯНИЯ", "正在读取规范状态"),
        "Headers, retained transactions and live state remain node-verified." => (
            "Заголовки, сохранённые транзакции и текущее состояние проверены узлом.",
            "区块头、保留期内的交易和实时状态均由节点验证。",
        ),
        "CANONICAL BLOCKS" => ("КАНОНИЧЕСКИЕ БЛОКИ", "规范链区块"),
        "BLOCK" => ("БЛОК", "区块"),
        "BLOCK HASH" => ("ХЕШ БЛОКА", "区块哈希"),
        "AGE" => ("ВОЗРАСТ", "时间"),
        "HASH" => ("ХЕШ", "哈希"),
        "RECENT TRANSACTIONS" => ("НЕДАВНИЕ ТРАНЗАКЦИИ", "近期交易"),
        "RECENT TX" => ("НЕДАВНИЕ TX", "近期交易"),
        "RECENT ADDRESS ACTIVITY" => ("НЕДАВНЯЯ АКТИВНОСТЬ АДРЕСА", "地址近期活动"),
        "NO CANONICAL HEADERS AVAILABLE" => ("НЕТ КАНОНИЧЕСКИХ ЗАГОЛОВКОВ", "暂无规范区块头"),
        "NO TRANSACTIONS IN THE RETAINED WINDOW" => (
            "НЕТ ТРАНЗАКЦИЙ В ОКНЕ ХРАНЕНИЯ",
            "保留窗口内没有交易",
        ),
        "NO ACTIVITY FOR THIS ADDRESS IN THE RETAINED WINDOW" => (
            "В ОКНЕ ХРАНЕНИЯ НЕТ АКТИВНОСТИ ЭТОГО АДРЕСА",
            "保留窗口内此地址没有活动",
        ),
        "After 18 blocks, a payment receipt carries the proof; the transaction body is not retained." => (
            "Через 18 блоков доказательство остаётся в чеке, а тело транзакции больше не хранится.",
            "超过 18 个区块后，证明由支付凭证保存，交易正文不再保留。",
        ),
        "ADDRESS / LIVE STATE" => ("АДРЕС / ТЕКУЩЕЕ СОСТОЯНИЕ", "地址 / 实时状态"),
        "ADDRESS" => ("АДРЕС", "地址"),
        "BALANCE" => ("БАЛАНС", "余额"),
        "LIVE OUTPUTS" => ("ТЕКУЩИЕ ВЫХОДЫ", "实时输出"),
        "CURRENT STATE ONLY" => ("ТОЛЬКО ТЕКУЩЕЕ СОСТОЯНИЕ", "仅当前状态"),
        "Current live outputs come directly from the proved state—not from replayed history." => (
            "Текущие выходы берутся напрямую из доказанного состояния, а не из повторного воспроизведения истории.",
            "实时输出直接来自已证明状态，而不是通过重放历史记录得到。",
        ),
        "THIS ADDRESS HAS NO LIVE OUTPUTS" => ("У ЭТОГО АДРЕСА НЕТ ТЕКУЩИХ ВЫХОДОВ", "此地址没有实时输出"),
        "No owner in the current state." => ("В текущем состоянии нет владельца.", "当前状态中没有所有者。"),
        "OWNER" => ("ВЛАДЕЛЕЦ", "所有者"),
        "OWNER INDEX" => ("ИНДЕКС ВЛАДЕЛЬЦА", "所有者索引"),
        "STATE" => ("СОСТОЯНИЕ", "状态"),

        // Mining and block details.
        "MATRIX CACHE" => ("КЭШ МАТРИЦ", "矩阵缓存"),
        "RETRY MATRIX PREPARATION" => ("ПОВТОРИТЬ ПОДГОТОВКУ МАТРИЦ", "重试矩阵准备"),
        "PREPARING B25 MATRIX…" => ("ПОДГОТОВКА МАТРИЦЫ B25…", "正在准备 B25 矩阵…"),
        "NODE ERROR" => ("ОШИБКА УЗЛА", "节点错误"),
        "INTERNAL MINER" => ("ВСТРОЕННЫЙ МАЙНЕР", "内置矿工"),
        "MINER" => ("МАЙНЕР", "矿工"),
        "MINING" => ("МАЙНИНГ", "挖矿"),
        "PAYOUT" => ("ВЫПЛАТА", "收益地址"),
        "THREADS" => ("ПОТОКИ", "线程"),
        "TARGET" => ("ЦЕЛЬ", "目标时间"),
        "LOCAL NODE ONLINE" => ("ЛОКАЛЬНЫЙ УЗЕЛ В СЕТИ", "本地节点在线"),
        "LOCAL NODE OFFLINE" => ("ЛОКАЛЬНЫЙ УЗЕЛ НЕ В СЕТИ", "本地节点离线"),
        "LOCAL NODE STARTING" => ("ЛОКАЛЬНЫЙ УЗЕЛ ЗАПУСКАЕТСЯ", "本地节点正在启动"),
        "CPU THREADS" => ("ПОТОКИ CPU", "CPU 线程"),
        "NETWORK READINESS" => ("ГОТОВНОСТЬ СЕТИ", "网络就绪状态"),
        "SYNCING TIP" => ("ОБНОВЛЕНИЕ ВЕРШИНЫ", "正在同步链顶"),
        "MINER CONTROL" => ("УПРАВЛЕНИЕ МАЙНЕРОМ", "矿工控制"),
        "START MINING" => ("НАЧАТЬ МАЙНИНГ", "开始挖矿"),
        "STOP MINING" => ("ОСТАНОВИТЬ МАЙНИНГ", "停止挖矿"),
        "Genesis mode" => ("Режим Genesis", "Genesis 模式"),
        "MINED BLOCKS" => ("ДОБЫТЫЕ БЛОКИ", "已挖区块"),
        "FOUND" => ("НАЙДЕН", "发现时间"),
        "REWARD" => ("НАГРАДА", "奖励"),
        "NO LOCALLY RECORDED MINED BLOCKS" => ("НЕТ ЛОКАЛЬНО ЗАПИСАННЫХ БЛОКОВ", "本机尚无挖矿记录"),
        "Start the miner; accepted coinbase blocks will appear here." => (
            "Запустите майнер — принятые coinbase-блоки появятся здесь.",
            "启动挖矿后，已接受的 coinbase 区块会显示在这里。",
        ),
        "FULL BLOCK DATA FOLLOWS THE NODE'S 18-BLOCK WINDOW" => (
            "ПОЛНЫЕ ДАННЫЕ ДОСТУПНЫ В 18-БЛОЧНОМ ОКНЕ УЗЛА",
            "完整区块数据遵循节点的 18 区块保留窗口",
        ),
        "PARENT" => ("РОДИТЕЛЬ", "父区块"),
        "STATE ROOT" => ("КОРЕНЬ СОСТОЯНИЯ", "状态根"),
        "TX ROOT" => ("КОРЕНЬ TX", "交易根"),
        "EPOCH ANCHOR" => ("ЯКОРЬ ЭПОХИ", "纪元锚点"),
        "DIFFICULTY TARGET" => ("ЦЕЛЬ СЛОЖНОСТИ", "难度目标"),
        "NONCE" => ("NONCE", "随机数"),
        "ALLOC" => ("РАСПРЕДЕЛЕНО", "分配量"),
        "FEES" => ("КОМИССИИ", "手续费"),
        "LOGICAL TRANSACTIONS" => ("ЛОГИЧЕСКИЕ ТРАНЗАКЦИИ", "逻辑交易"),
        "TRANSACTION" => ("ТРАНЗАКЦИЯ", "交易"),
        "TRANSACTIONS" => ("ТРАНЗАКЦИИ", "交易"),
        "The canonical header remains available. Full block data is retained for 18 blocks; payment receipts prove older transactions." => (
            "Канонический заголовок остаётся доступен. Полные данные хранятся 18 блоков; более старые транзакции доказываются чеками.",
            "规范区块头会永久保留。完整区块数据保留 18 个区块；更早的交易可由支付凭证证明。",
        ),
        "← ESC BACK TO BLOCK" => ("← ESC К БЛОКУ", "← ESC 返回区块"),
        "LOGICAL TRANSACTION ID" => ("ID ЛОГИЧЕСКОЙ ТРАНЗАКЦИИ", "逻辑交易 ID"),
        "POSITION" => ("ПОЗИЦИЯ", "位置"),
        "POS" => ("ПОЗ.", "位置"),
        "IDX" => ("ИНДЕКС", "索引"),
        "TYPE" => ("ТИП", "类型"),
        "TRANSFER" => ("ПЕРЕВОД", "转账"),
        "COINBASE" => ("COINBASE", "COINBASE"),
        "DEVELOPMENT" => ("РАЗВИТИЕ", "开发资金"),
        "INPUT TOTAL" => ("СУММА ВХОДОВ", "输入总额"),
        "INPUT OWNER" => ("ВЛАДЕЛЕЦ ВХОДОВ", "输入所有者"),
        "OUTPUT TOTAL" => ("СУММА ВЫХОДОВ", "输出总额"),
        "BLOCK REWARD" => ("ВОЗНАГРАЖДЕНИЕ ЗА БЛОК", "区块奖励"),
        "REWARD SHARE" => ("ДОЛЯ НАГРАДЫ", "奖励份额"),
        "Block-reward shares paid to O(1) Network Fund and ParanO(1)d Lab. This protocol payout has no spend inputs." => (
            "Доли вознаграждения за блок выплачены O(1) Network Fund и ParanO(1)d Lab. У этой протокольной выплаты нет расходуемых входов.",
            "区块奖励份额支付给 O(1) Network Fund 和 ParanO(1)d Lab。该协议付款不消耗任何输入。",
        ),
        "INPUT UTXOS" => ("ВХОДНЫЕ UTXO", "输入 UTXO"),
        "OUTPUT UTXOS" => ("ВЫХОДНЫЕ UTXO", "输出 UTXO"),
        "NO INPUTS · BLOCK REWARD PAYOUT" => ("БЕЗ ВХОДОВ · ВЫПЛАТА ВОЗНАГРАЖДЕНИЯ", "无输入 · 区块奖励支付"),
        "REF" => ("ССЫЛКА", "引用"),
        "OWNED" => ("МОИ", "本钱包所有"),
        "RESERVED" => ("ЗАРЕЗЕРВИРОВАНО", "已预留"),
        "PHYSICAL TX8x2 PAGES" => ("ФИЗИЧЕСКИЕ СТРАНИЦЫ TX8x2", "TX8x2 物理页"),
        "TX8x2 BODY HASH" => ("ХЕШ ТЕЛА TX8x2", "TX8x2 正文哈希"),
        "PAGES" => ("СТРАНИЦЫ", "页数"),
        "PAGE" => ("СТРАНИЦА", "页"),
        "USER PAGES" => ("ПОЛЬЗОВАТЕЛЬСКИЕ СТРАНИЦЫ", "用户页"),
        "BUNDLE" => ("ПАКЕТ", "页束"),
        "MERKLE" => ("MERKLE", "MERKLE"),
        "PROOF" => ("ДОКАЗАТЕЛЬСТВО", "证明"),
        "MULTIPLE OUTPUTS" => ("НЕСКОЛЬКО ВЫХОДОВ", "多个输出"),
        "FROM" => ("ОТ КОГО", "付款方"),
        "TIME" => ("ВРЕМЯ", "时间"),
        "TIP" => ("ВЕРШИНА", "链顶"),
        "VALUE" => ("ЗНАЧЕНИЕ", "数值"),
        "SEG" => ("СЕГ.", "分段"),
        "SEND" => ("ОТПРАВИТЬ", "发送"),
        "USE KEY" => ("ИСПОЛЬЗОВАТЬ КЛЮЧ", "使用密钥"),
        "HEADER →" => ("ЗАГОЛОВОК →", "区块头 →"),
        "FEE / NOID" => ("КОМИССИЯ / NOID", "手续费 / NOID"),
        "FEE / μNOID" => ("КОМИССИЯ / μNOID", "手续费 / μNOID"),
        "256 BITS · GENERATED LOCALLY" => (
            "256 БИТ · СОЗДАН ЛОКАЛЬНО",
            "256 位 · 本机生成",
        ),
        "DESIGN PREVIEW" => ("ПРЕДПРОСМОТР ДИЗАЙНА", "设计预览"),
        "JPEG · PNG · WEBP · GIF · BMP · TIFF" => (
            "JPEG · PNG · WEBP · GIF · BMP · TIFF",
            "JPEG · PNG · WEBP · GIF · BMP · TIFF",
        ),

        // User-facing validation and operational feedback.
        "Choose a photo." | "Choose a photo first." => ("Выберите фото.", "请选择照片。"),
        "The selected photo is empty." => ("Выбранное фото пусто.", "所选照片为空文件。"),
        "The selected photo is larger than 256 MiB." => (
            "Размер выбранного фото превышает 256 MiB.",
            "所选照片大于 256 MiB。",
        ),
        "Data directory cannot be empty." => (
            "Каталог данных не может быть пустым.",
            "数据目录不能为空。",
        ),
        "P2P listen must be HOST:PORT or a libp2p multiaddr." => (
            "P2P-адрес должен иметь вид HOST:PORT или быть libp2p multiaddr.",
            "P2P 监听地址必须是 HOST:PORT 或 libp2p multiaddr。",
        ),
        "A custom seed address is too long." => (
            "Адрес пользовательского seed-узла слишком длинный.",
            "自定义种子节点地址过长。",
        ),
        "At most 32 custom seed peers may be configured." => (
            "Можно настроить не более 32 seed-пиров.",
            "最多可配置 32 个自定义种子节点。",
        ),
        "Settings cannot restart an externally managed node." => (
            "Настройки не могут перезапустить узел, запущенный извне.",
            "无法通过设置重启由外部管理的节点。",
        ),
        "Master secret export is unavailable in design preview." => (
            "Экспорт мастер-ключа недоступен в режиме предпросмотра.",
            "设计预览模式下无法导出主密钥。",
        ),
        "Node returned an invalid master secret." => (
            "Узел вернул недействительный мастер-ключ.",
            "节点返回了无效的主密钥。",
        ),
        "Master secret import is unavailable in design preview." => (
            "Импорт мастер-ключа недоступен в режиме предпросмотра.",
            "设计预览模式下无法导入主密钥。",
        ),
        "Stop the externally managed node before importing a secret." => (
            "Перед импортом ключа остановите узел, запущенный извне.",
            "导入密钥前，请先停止由外部管理的节点。",
        ),
        "Wallet setup is unavailable in design preview." => (
            "Настройка кошелька недоступна в режиме предпросмотра.",
            "设计预览模式下无法初始化钱包。",
        ),
        "The wallet is already initialized." => ("Кошелёк уже настроен.", "钱包已经初始化。"),
        "The local node is already starting." => (
            "Локальный узел уже запускается.",
            "本地节点已经在启动中。",
        ),
        "Enter an address, block, transaction, or slot." => (
            "Введите адрес, блок, транзакцию или слот.",
            "请输入地址、区块、交易或槽位。",
        ),
        "No canonical block or transaction matches this hash." => (
            "Канонический блок или транзакция с таким хешем не найдены.",
            "没有与此哈希匹配的规范链区块或交易。",
        ),
        "Search accepts an o1 address, block height/hash, txid, or slot:<number>." => (
            "Поиск принимает адрес o1, высоту или хеш блока, TXID либо slot:<номер>.",
            "可搜索 o1 地址、区块高度/哈希、TXID 或 slot:<编号>。",
        ),
        "Receipt text exceeds the 128 KiB protocol limit." => (
            "Текст чека превышает протокольный лимит 128 KiB.",
            "凭证文本超过协议规定的 128 KiB 上限。",
        ),
        "Paste a receipt before verifying." => (
            "Перед проверкой вставьте чек.",
            "请先粘贴凭证再进行验证。",
        ),
        "Receipt must be an even-length hexadecimal string." => (
            "Чек должен быть шестнадцатеричной строкой чётной длины.",
            "凭证必须是长度为偶数的十六进制字符串。",
        ),
        "Receipt exceeds the 128 KiB protocol limit." => (
            "Чек превышает протокольный лимит 128 KiB.",
            "凭证超过协议规定的 128 KiB 上限。",
        ),
        "The wallet must be online to calculate the transaction." => (
            "Для расчёта транзакции кошелёк должен быть в сети.",
            "钱包必须在线才能计算交易。",
        ),
        "Enter a recipient address." => ("Введите адрес получателя.", "请输入收款地址。"),
        "Clipboard does not contain text." => (
            "В буфере обмена нет текста.",
            "剪贴板中没有文本。",
        ),
        "Node settings applied." => ("Настройки узла применены.", "节点设置已应用。"),
        "Master secret must contain exactly 64 hexadecimal characters." => (
            "Мастер-ключ должен содержать ровно 64 шестнадцатеричных символа.",
            "主密钥必须正好包含 64 个十六进制字符。",
        ),
        "Master secret ready." => ("Мастер-ключ готов.", "主密钥已就绪。"),
        "Enter an amount." => ("Введите сумму.", "请输入金额。"),
        "Amount must be a positive NOID value." => (
            "Сумма NOID должна быть положительной.",
            "NOID 金额必须大于零。",
        ),
        "Use a decimal NOID amount, for example 12.500000." => (
            "Введите десятичную сумму NOID, например 12.500000.",
            "请输入十进制 NOID 金额，例如 12.500000。",
        ),
        "NOID supports at most 6 decimal places." => (
            "NOID поддерживает не более 6 знаков после запятой.",
            "NOID 最多支持 6 位小数。",
        ),
        "Amount is too large." => ("Сумма слишком велика.", "金额过大。"),
        "Amount must be at least 0.000001 NOID." => (
            "Минимальная сумма — 0.000001 NOID.",
            "金额不得低于 0.000001 NOID。",
        ),
        "HISTORYSTEP" => ("HISTORYSTEP", "HISTORYSTEP"),
        "genesis" => ("генезис", "创世区块"),

        // Settings.
        "INTERFACE" => ("ИНТЕРФЕЙС", "界面"),
        "LANGUAGE" => ("ЯЗЫК", "语言"),
        "KEYBOARD" => ("ГОРЯЧИЕ КЛАВИШИ", "快捷键"),
        "Shortcuts are available from every wallet section." => (
            "Горячие клавиши работают в любом разделе кошелька.",
            "在钱包的任何页面都可以使用快捷键。",
        ),
        "F1–F7 NAVIGATION · F10 QUIT · ESC BACK" => (
            "F1–F7 РАЗДЕЛЫ · F10 ВЫХОД · ESC НАЗАД",
            "F1–F7 切换页面 · F10 退出 · ESC 返回",
        ),
        "SECRET" => ("СЕКРЕТ", "密钥"),
        "NODE" => ("УЗЕЛ", "节点"),
        "MASTER SECRET" => ("МАСТЕР-КЛЮЧ", "主密钥"),
        "PROTECTION" => ("ЗАЩИТА", "保护"),
        "LOCAL KEYSTORE · OWNER ONLY" => ("ЛОКАЛЬНОЕ ХРАНИЛИЩЕ · ТОЛЬКО ВЛАДЕЛЕЦ", "本机密钥库 · 仅限所有者"),
        "KEY ACTIVE" => ("КЛЮЧ АКТИВЕН", "密钥已启用"),
        "ONE KEY · EVERY ADDRESS" => ("ОДИН КЛЮЧ · ВСЕ АДРЕСА", "一个密钥 · 所有地址"),
        "No source media is stored." => ("Исходный файл не сохраняется.", "不会保存源文件。"),
        "KEY CONTROL" => ("УПРАВЛЕНИЕ КЛЮЧОМ", "密钥管理"),
        "The keystore always contains one 256-bit key." => (
            "В хранилище всегда находится один 256-битный ключ.",
            "密钥库始终只保存一个 256 位密钥。",
        ),
        "EXPORT KEY" => ("ЭКСПОРТ КЛЮЧА", "导出密钥"),
        "IMPORT KEY" => ("ИМПОРТ КЛЮЧА", "导入密钥"),
        "GENERATE NEW KEY" => ("СОЗДАТЬ НОВЫЙ КЛЮЧ", "生成新密钥"),
        "Reading local master secret…" => ("Чтение локального мастер-ключа…", "正在读取本机主密钥…"),
        "COPY KEY" => ("СКОПИРОВАТЬ КЛЮЧ", "复制密钥"),
        "Anyone with this key controls every derived address." => (
            "Любой, у кого есть этот ключ, контролирует все производные адреса.",
            "任何持有此密钥的人都能控制由它生成的全部地址。",
        ),
        "CHOOSE ANOTHER PHOTO" => ("ВЫБРАТЬ ДРУГОЕ ФОТО", "选择另一张照片"),
        "Keep the private original. Changed pixels create a different wallet." => (
            "Храните оригинал в тайне. Изменение пикселей создаст другой кошелёк.",
            "请私密保存原始文件；像素发生变化会生成另一个钱包。",
        ),
        "A fresh random 256-bit key will replace every local address." => (
            "Новый случайный 256-битный ключ заменит все локальные адреса.",
            "新的随机 256 位密钥将替换本机的全部地址。",
        ),
        "GENERATE NEW" => ("СОЗДАТЬ НОВЫЙ", "生成新密钥"),
        "The current master secret cannot be recovered after replacement. Export it first if you need to keep it." => (
            "После замены текущий мастер-ключ нельзя будет восстановить. Сначала экспортируйте его, если он нужен.",
            "替换后将无法恢复当前主密钥。如需保留，请先导出。",
        ),
        "CHANGES RESTART THE LOCAL NODE" => ("ИЗМЕНЕНИЯ ПЕРЕЗАПУСТЯТ ЛОКАЛЬНЫЙ УЗЕЛ", "更改后将重启本地节点"),
        "DATA DIRECTORY" => ("КАТАЛОГ ДАННЫХ", "数据目录"),
        "Live state, wallet records and matrix cache" => (
            "Текущее состояние, данные кошелька и кэш матриц",
            "实时状态、钱包记录和矩阵缓存",
        ),
        "Node data directory" => ("Каталог данных узла", "节点数据目录"),
        "LOG LEVEL" => ("УРОВЕНЬ ЛОГОВ", "日志级别"),
        "Written locally to parano1d-node.log" => (
            "Записываются локально в parano1d-node.log",
            "在本机写入 parano1d-node.log",
        ),
        "ERROR" => ("ОШИБКИ", "错误"),
        "WARN" => ("ПРЕДУПР.", "警告"),
        "INFO" => ("ИНФО", "信息"),
        "DEBUG" => ("ОТЛАДКА", "调试"),
        "LOGS" => ("ЛОГИ", "日志"),
        "PAUSED · INSPECTING" => ("ПАУЗА · ПРОСМОТР", "已暂停 · 查看中"),
        "READ ERROR" => ("ОШИБКА ЧТЕНИЯ", "读取错误"),
        "NO OUTPUT" => ("НЕТ ДАННЫХ", "暂无日志输出"),
        "SELECT TEXT · CTRL+C TO COPY" => ("ВЫДЕЛИТЕ ТЕКСТ · CTRL+C — КОПИРОВАТЬ", "选择文本 · CTRL+C 复制"),
        "No parano1d-node.log output yet…" => (
            "В parano1d-node.log пока нет данных…",
            "parano1d-node.log 暂无输出…",
        ),
        "P2P LISTEN" => ("P2P-АДРЕС", "P2P 监听地址"),
        "Address used for inbound peer connections" => (
            "Адрес для входящих подключений пиров",
            "用于接收入站节点连接的地址",
        ),
        "CUSTOM SEEDS" => ("СВОИ SEED-УЗЛЫ", "自定义种子节点"),
        "Optional bootstrap peers · DNS seeds and local discovery remain automatic" => (
            "Необязательные стартовые пиры · DNS-seed и локальный поиск работают автоматически",
            "可选的引导节点 · DNS 种子和本地发现仍会自动运行",
        ),
        "One seed peer per line" => ("Один seed-пир на строку", "每行一个种子节点"),

        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::{activate, navigation_label, translate};
    use crate::model::Language;

    #[test]
    fn english_is_the_unmodified_default() {
        activate(Language::English);
        assert_eq!(translate("TRANSACTION SENT"), "TRANSACTION SENT");
    }

    #[test]
    fn synchronization_stages_are_localized() {
        activate(Language::Russian);
        assert_eq!(translate("SYNCING HEADERS"), "СИНХРОНИЗАЦИЯ ЗАГОЛОВКОВ");
        assert_eq!(translate("SYNCING STATE"), "СИНХРОНИЗАЦИЯ STATE");
        assert_eq!(translate("SYNCING TIP"), "ОБНОВЛЕНИЕ ВЕРШИНЫ");
    }

    #[test]
    fn semantic_wallet_terms_are_localized() {
        activate(Language::Russian);
        assert_eq!(navigation_label("Receipts"), "Чеки");
        assert_eq!(translate("FORGING THE PROOF"), "КУЁМ ДОКАЗАТЕЛЬСТВО");

        activate(Language::Chinese);
        assert_eq!(navigation_label("Receipts"), "凭证");
        assert_eq!(translate("FORGING THE PROOF"), "正在锻造证明");
    }

    #[test]
    fn formatted_statuses_keep_values_and_localize_meaning() {
        activate(Language::Russian);
        assert_eq!(translate("FULL · 7 conf"), "FULL · 7 conf");
        assert_eq!(translate("HEADER · 7 conf"), "HEADER · 7 conf");
        assert_eq!(translate("ORPHANED · NO REWARD"), "ORPHANED · NO REWARD");
        assert_eq!(translate("12m ago"), "12 мин назад");
        assert_eq!(
            translate("75 → 12 outputs · 63 slots freed"),
            "75 → 12 выходов · освобождено слотов: 63"
        );
        assert_eq!(
            translate("2 outputs remain untouched."),
            "2 выхода останутся без изменений."
        );

        activate(Language::Chinese);
        assert_eq!(translate("BLOCK #417"), "区块 #417");
        assert_eq!(translate("12m ago"), "12 分钟前");
        assert_eq!(
            translate("75 → 12 outputs · 63 slots freed"),
            "75 → 12 个输出 · 释放 63 个槽位"
        );
    }
}
