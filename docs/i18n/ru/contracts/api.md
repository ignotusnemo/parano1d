# API контрактов и интеграция приложений

Операции используют локальный JSON-RPC и префикс `paranoid_`, параметры —
позиционные массивы. Все методы контрактов требуют **локального доступа
владельца**. Токены майнера и оператора не дают этих прав. См.
[авторизацию RPC](../reference/rpc.md#аутентификация).

## Определение протокола

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "paranoid_getContractProtocol",
  "params": []
}
```

Ответ содержит `tip_height`, `activation_height`, `active_at_next_block`,
`runtime_available`, `next_block_time_seconds`, `abi_version`, `instructions`,
`persistent_registers`, `classes`. Класс задаёт `class`, `pages`, `live_inputs`,
`contract_calls`. Значения v2: ABI 3, 16 инструкций, 2 постоянных регистра,
Small 63/504/63 и Large 206/504/63.

Правила mainnet v2 начинаются с **H210537**. Новый бинарник может готовить
условия, наблюдать раскрытия и читать локальные данные до этой высоты.
Пополнение, предпросмотр и вызов требуют активации на **следующей высоте
кандидата** и доступного аутентифицированного runtime v2. Старый бинарник этих
методов не предоставляет.

## Методы

| Суффикс метода | Позиционные параметры | Результат |
| --- | --- | --- |
| `getContractProtocol` | `[]` | `ObjectProtocolInfo` |
| `createObject` | `[definition]` | `ObjectInfo` |
| `getObjectStatus` | `[opening_hex, slot_index]` | `ObjectStatus` |
| `getObjectInstances` | `[opening_hex, from_slot, limit]` | `ObjectInstances` |
| `previewObjectCall` | `[request]` | `ObjectCallPreview` |
| `walletFundObject` | `[opening_hex, amount_micronoid, fee_micronoid, expected_sender?]` | `WalletSendResult` |
| `walletCallObject` | `[request]` | `ObjectCallResult` |
| `walletGetObjectOpening` | `[address]` | `ObjectInfo` |
| `walletWatchObject` | `[opening_hex]` | `ObjectInfo` |
| `walletListObjectStates` | `[opening_hex, after_root, limit]` | `ObjectKnownStates` |
| `walletListObjectReceipts` | `[opening_hex, after_cursor, limit]` | `ObjectActivityPage` |
| `exportObjectReceipt` | `[opening_hex, txid]` | `hex` |
| `verifyObjectReceipt` | `[receipt_hex]` | `ObjectReceiptResult` |
| `walletImportObjectReceipt` | `[receipt_hex, expected_opening_hex?]` | `ObjectReceiptResult` |

`createObject` кодирует и проверяет условия без рассылки транзакции и комиссии.
Сохраните возвращённое раскрытие. `walletWatchObject` сохраняет его для будущего
наблюдения. `walletGetObjectOpening` возвращает локально сохранённые условия,
а не восстанавливает произвольный прообраз из хеша цепи.

`getObjectStatus` проверяет слот по раскрытию; дополнительно сравнивайте
`creation_id` с нужным экземпляром. `getObjectInstances` ищет точное
обязательство в State: `from_slot` включительный, `limit` 1–256, `next_slot` —
следующий включительный курсор или null. Ответ содержит `height` и `tip_hash`;
при смене вершины начните многостраничное чтение заново.

`walletListObjectStates` перечисляет локально известные состояния с теми же
неизменяемыми условиями и актуальным `has_balance`. Курсор `after_root`
исключительный, сначала null; limit 1–64. `walletListObjectReceipts` возвращает
сохранённые вызовы обеих сторон от новых к старым: исключительный `after_cursor`,
сначала null, limit 1–64. Признак `canonical` независим от локального хранения.
Ни один метод не восстанавливает полную историю сети.

## Определения и суммы

Определение выбирается полем `kind`, неизвестные поля отклоняются. Суммы —
целые μNOID, высоты и периоды — блоки. Поля конструкторов:

| `kind` | Поля |
| --- | --- |
| `refundable_payment` | `payer`, `payee`, `expiry_height`, `max_fee_micronoid` |
| `timelocked_vault` | `owner`, `unlock_height`, `max_fee_micronoid` |
| `allowance_wallet` | `spending_key`, `recovery_key`, `payout_recipient`, `recover_at`, `max_fee_micronoid`, `max_payout_micronoid`, `min_retained_micronoid` |
| `period_budget_wallet` | Allowance + `start_height`, `period_blocks`, `budget_micronoid` |
| `recurring_payment` | `payer`, `payee`, `first_due_height`, `period_blocks`, `payment_micronoid`, `recover_at`, `max_fee_micronoid` |
| `tranche_vesting` | `beneficiary`, `first_unlock_height`, `period_blocks`, `tranche_micronoid`, `mature_at`, `max_fee_micronoid` |
| `custom_program` | `definition` |
| `custom` | `opening_hex` |

«Allowance +» означает все поля `allowance_wallet` и три дополнительных.
Необязательный `payout_recipient` может быть null. Правила ветвей, резервов
и периодов приведены в [шаблонах](templates.md).

`custom_program.definition` требует `state`, `program`, `claim_authority`,
`recovery_authority`, `claim_recipient`, `recovery_recipient`, `deadline_height`,
`max_fee_micronoid`, `max_payout_micronoid`, `min_retained_micronoid`,
`claim_can_continue`, `claim_can_close`, `recovery_can_continue`,
`recovery_can_close`, `unrestricted_payout_recipient`. Неявных разрешений нет.
`state` — ровно две канонические десятичные строки u64. `program` содержит
до 16 [инструкций](core.md); оставшиеся заполняются автоматически.
`custom` проверяет уже закодированное раскрытие по тому же ABI.

`ObjectInfo` возвращает поля политики, `abi_version`, `address`, `opening_hex`,
`code_id`, `state_hex`, две строки состояния и все 16 инструкций.
`opening_hex` кодирует 699 байт. Адреса — канонические `o1…`. Обрабатывайте
u64-суммы и высоты без потери точности: браузерный `Number` не охватывает все u64.
Строки счётчиков и констант нельзя преобразовывать через floating point.

## Проверка перед отправкой

Запрос вызова требует `opening_hex`, `slot_index`, **`creation_id`**, `terminal`,
`payout`, `fee_micronoid`. `payout` — null либо `{address, amount_micronoid}`;
при закрытии нужен null. Нулевая комиссия запрашивает текущий необходимый
минимум в пределах потолка политики. Комиссия берётся из входа контракта,
а не отдельного входа кошелька.

1. Найдите и выберите точный живой экземпляр.
2. Передайте запрос в `previewObjectCall`. Проверьте `txid`, `call_height`,
   `authority`, `recovery`, `terminal`, комиссию, остаток, выплату и преемника.
3. Сохраните результат. Привяжите его полями `expected_txid`,
   `expected_call_height`, `expected_authority`, `expected_recovery` при
   `walletCallObject`. Несовпадение требует нового просмотра; не меняйте
   авторизованное тело незаметно.
4. Сохраните `transaction.txid`, `call_height`, `successor`, `output_slot` ответа.
   Это отправка, а не подтверждение.
5. Дождитесь включения, экспортируйте квитанцию и передайте новые условия при необходимости.

При пополнении `expected_sender` защищает выбор активного адреса кошелька.
Пополнение — обычный платёж; одно раскрытие может иметь несколько независимых
экземпляров. Если ответ потерян, сначала проверьте просмотренный txid: таймаут
RPC не доказывает, что отправка не состоялась.

После очистки тел `getTx` может сохранять индексный указатель. Это не тело и
не доказательство текущего остатка. Для прошлого вызова используйте квитанцию,
для доступного баланса — State.

## Индексация публичных вызовов

Индексатор получает txid ожидающих транзакций через `getMempoolInfo`, затем
запрашивает каждую через `getMempoolEntry(txid)`. Для контрактного вызова ответ
содержит каноническое 699-байтное `contract_opening_hex`; для обычного платежа
поле равно `null`. `getBlockDetails(height)` помечает транзакции сохранённого
блока значением `contract: "call"`, `"close"` или `null`. Подробности приведены
в [справочнике RPC](../reference/rpc.md).

Сохраните раскрытие, пока вызов находится в мемпуле. В блоке остаются признаки
контрактного перехода, но позднее получить само раскрытие через RPC нельзя.
Пропущенный интервал мемпула не восстановить из State или удалённого тела блока.

## Результаты и пределы квитанций

Проверка или импорт возвращают `valid`, `height`, `txid`, `terminal`,
`authority`, `original`, необязательный `successor`, `input_micronoid`,
`fee_micronoid`, `retained_micronoid`, необязательный `payout`. При закрытии
`original` остаётся, `successor` равен null, а смысловая выплата — перевод
закрытия. В журнале добавлены `block_hash` и `canonical`.

Проверка ничего не сохраняет. Импорт проверяет и сохраняет доказательство и
условия; необязательный `expected_opening_hex` должен совпасть с исходными
или новыми условиями. Повторные импорты объединяются по txid, сохраняя свои
записи. См. [восстановление](receipts-and-recovery.md).

Тело HTTP-запроса ограничено **2 237 632 байтами**. Контрактная квитанция после
декодирования — до **1 110 624 байт**; hex удваивает размер. У обычной платёжной
квитанции отдельный предел 128 KiB. Пакет JSON-RPC использует общий предел тела;
применяйте пагинацию вместо неограниченных списков.

## Работа через CLI

Суммы CLI — десятичные **NOID**, в отличие от целых μNOID RPC. Замените
поля в угловых скобках. Для закрытия активен кошелёк получателя или возврата,
согласно высоте включения.

```sh
parano1d-cli contract protocol
parano1d-cli contract payment <payee-o1-address> <expiry-height> --max-fee 1 --out payment.json
parano1d-cli contract fund payment.json 10
parano1d-cli contract watch payment.json
parano1d-cli contract instances payment.json --limit 64
parano1d-cli contract call payment.json <slot> <creation-id> --close --preview
parano1d-cli contract call payment.json <slot> <creation-id> --close --expected-txid <reviewed-txid> --out closing.json
parano1d-cli contract receipt payment.json <confirmed-txid> --out closing.receipt
parano1d-cli contract verify closing.receipt
```

CLI привязывает предпросмотр перед отправкой и сначала надёжно сохраняет
его файл, чтобы можно было восстановиться после потери ответа. `--out`
должен указывать новый файл. `call --wait-seconds 0` возвращает ответ после
отправки; ожидание по умолчанию 600 секунд. Закрытый результат не имеет преемника.

Другие конструкторы: `vault`, `allowance`, `budget`, `recurring`, `vesting`.
`create definition.json --out object.json` принимает собственное определение.
Точные аргументы: `parano1d-cli contract <command> --help`.
`restore <address> --out object.json` возвращает локально сохранённое раскрытие.
