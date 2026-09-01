# JSON-RPC API

Core предоставляет JSON-RPC 2.0 через HTTP и отклоняет переключение на WebSocket. Стандартный адрес:

```text
http://127.0.0.1:9601
```

Имена всех методов начинаются с префикса пространства имён `paranoid_`. Параметры передаются позиционными JSON-массивами. Размер тела запроса ограничен 1 МиБ, а JSON-RPC batch продолжает поддерживаться в пределах этого размера.

```sh
curl --silent --show-error \
  -H 'Content-Type: application/json' \
  --data '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "paranoid_getChainInfo",
    "params": []
  }' \
  http://127.0.0.1:9601
```

## Соглашения

- Целочисленные денежные поля выражены в μNOID.
- Один NOID равен 1 000 000 μNOID.
- Хэши передаются в нижнем регистре hex без `0x`.
- Целевое значение PoW и байты nonce используют канонический порядок от
  младшего байта к старшему (little-endian).
- Адреса имеют каноническую форму bech32m `o1…`, если поле явно не требует
  hex.
- Неизвестный постоянный объект обычно возвращает `null`.
- После 18-блочного окна старое тело блока возвращает `null`, но его заголовок
  остаётся доступен.
- Десятичные строки используются для агрегатов, которые могут выйти за
  диапазон точного представления чисел JSON.
- Поля с плавающей точкой `*_noid` предназначены для отображения. Учётный код
  должен использовать соответствующее целое поле `*_micronoid`.

## Аутентификация

По умолчанию RPC не имеет аутентификации и должен оставаться на локальном интерфейсе. Core отказывается запускать неаутентифицированный listener на нелокальном адресе.

Соединение без Origin, принятое с фактического TCP-адреса loopback, получает локальные права владельца без заголовка Authorization, даже если настроены mining-токен или operator-токен. Поэтому GUI и CLI на машине ноды работают без пароля. Если заголовок Authorization передан, он всегда проверяется и выбирает только область доступа соответствующего токена. Нелокальный клиент обязан передать настроенный токен. Заголовки `Host`, `Forwarded`, `X-Forwarded-For` и другие HTTP-заголовки не могут выдать удалённое соединение за локальное.

При запуске Core с `--mining-key TOKEN` или `--mining-key-file FILE` для
запросов внешнего майнинга требуется заголовок:

```http
Authorization: Bearer TOKEN
```

При отсутствующем или другом токене сервер отвечает HTTP `401` без JSON-RPC-результата. Правильный mining-токен разрешает только `paranoid_getBlockTemplate` и `paranoid_submitBlock`; он не даёт доступа к кошельку, управлению нодой и остальным RPC-методам. Токен аутентифицирует, но не шифрует соединение, поэтому для удалённого доступа используйте приватный транспорт или TLS-прокси.

Пулы с отдельным хостом учёта или выплат могут настроить независимый `--operator-key TOKEN` или `--operator-key-file FILE`. Этот токен разрешает только:

- `paranoid_walletMinedBlocks`
- `paranoid_walletGetBalance`
- `paranoid_walletStatus`
- `paranoid_walletPlanSend`
- `paranoid_walletSend`
- `paranoid_walletPlanConsolidation`
- `paranoid_walletConsolidate`
- `paranoid_walletReceipts`
- `paranoid_walletExportReceipt`
- `paranoid_getTx`
- `paranoid_getMempoolEntry`
- `paranoid_verifyReceipt`
- `paranoid_submitTxIntent`
- `paranoid_validateAddress`
- `paranoid_getChainInfo`
- `paranoid_estimateFee`
- `paranoid_estimateFeeDetailed`

Operator-токен не может вызывать методы майнинга, `paranoid_stop`, сканирование и обнаружение кошелька, управление адресами, неограниченные списки истории или UTXO и любые текущие или будущие методы вне списка. Mining-токен и operator-токен должны различаться. Если настроены оба токена, каждый запрос получает только область доступа предъявленного токена. Области доступа не объединяются.

Operator-токен может расходовать средства активного кошелька через `walletSend`. Bearer-аутентификация не шифрует транспорт. Привязывайте listener к приватному интерфейсу, ограничивайте адреса источника межсетевым экраном и используйте VPN, SSH-туннель или аутентифицированный TLS-прокси, если сеть не полностью доверенная. Reverse proxy, подключающийся к ноде через loopback, должен пересылать Bearer-заголовок. Если он удалит Authorization, нода увидит прокси как локального клиента владельца и не применит область доступа удалённого токена.

Создавайте независимые токены командой `openssl rand -hex 32`. Передача токена в командной строке сохранена для совместимости. Предпочтителен файл с доступом только владельцу, потому что он не показывает токен в аргументах процесса.

## Методы цепи

| Суффикс метода | Позиционные параметры | Результат |
|---|---|---|
| `blockCount` | `[]` | Высота вершины `u64` |
| `getChainInfo` | `[]` | `ChainInfo` |
| `getBlockHash` | `[height: u64]` | `string \| null` |
| `getBlockHeader` | `[height: u64]` | `BlockHeaderInfo \| null` |
| `getBlockHeaderByHash` | `[hash: string]` | `BlockHeaderInfo \| null` |
| `getHeaderByHeight` | `[height: u64]` | Необработанный 212-байтный заголовок в hex или `null` |
| `getHeaderByHash` | `[hash: string]` | Необработанный 212-байтный заголовок в hex или `null` |
| `getHistoryStepTerminal` | `[]` | Текущее терминальное доказательство в hex или `null` |
| `getSlot` | `[slot_index: u32]` | `SlotInfo` |
| `getSlotsByOwner` | `[address: string]` | `SlotInfo[]` |
| `getActiveSlotCount` | `[]` | `u64` |
| `getStateInfo` | `[]` | `StateInfo` |
| `getStateMap` | `[]` | `StateMapInfo` |
| `getTx` | `[txid: string]` | `TxInfo \| null` |
| `getBlock` | `[height: u64]` | Сохранённый канонический блок в hex или `null` |
| `getBlockDetails` | `[height: u64]` | `BlockDetailsInfo \| null` |
| `getRecentTransactions` | `[page: u32, page_size: u32, address: string \| null]` | `RecentTransactionsPage` |

`getRecentTransactions` сканирует только сохранённые полные блоки. Нумерация
страниц начинается с единицы, размер ограничен диапазоном 1–32. Переданный
адрес добавляет точные суммы расходования и получения этого владельца.

`getSlot` возвращает ошибку для индекса вне текущего домена `2^log_slots`.
Пустой слот внутри диапазона возвращает `empty: true`, нулевую стоимость и
пустую строку владельца.

## Методы ноды, сети и комиссий

| Суффикс метода | Позиционные параметры | Результат |
|---|---|---|
| `getMiningInfo` | `[]` | `MiningInfo` |
| `getPeerCount` | `[]` | Число подключённых пиров |
| `getNodeStatus` | `[]` | `NodeStatus` |
| `estimateFee` | `[n_outputs: u32]` | Принимаемый минимум в μNOID для одного входа |
| `estimateFeeDetailed` | `[n_inputs: u32, n_outputs: u32]` | `FeeEstimate` |

Подробный расчёт принимает от 1 до 1 020 входов и от 1 до 256 выходов.
Возвращаемая комиссия учитывает текущую локальную границу ретрансляции.

## Вспомогательные методы и отправка

| Суффикс метода | Позиционные параметры | Результат |
|---|---|---|
| `validateAddress` | `[address: string]` | `AddressInfo` |
| `getSlotHints` | `[count: u32]` | `u32[]` |
| `getSlotHintsSalted` | `[count: u32, salt_hex: string]` | `u32[]` |
| `getEpochAnchor` | `[]` | Текущий якорь пользовательской транзакции в hex |
| `submitTxIntent` | `[intent_hex: string]` | Логический ID транзакции |

Подсказки слотов ничего не резервируют. Оба метода исключают выходы,
зарезервированные в мемпуле, возвращают не более 256 записей и могут вернуть
меньше, если свободных слотов недостаточно. Декодированный salt ограничен 256
байтами.

`submitTxIntent` принимает один канонически закодированный `PagedSpendIntent`
вместе с отдельной капсулой авторизации. До парсинга и проверки
доказательства декодированный вход ограничен 303 495 байтами.

## Методы мемпула

| Суффикс метода | Позиционные параметры | Результат |
|---|---|---|
| `getMempoolInfo` | `[]` | `MempoolInfo` |
| `getMempoolSize` | `[]` | Число ожидающих логических транзакций |
| `getMempoolStats` | `[]` | `MempoolStats` |
| `getMempoolEntry` | `[txid: string]` | `MempoolTxInfo \| null` |

Ответы мемпула описывают атомарные логические транзакции, а не физические
страницы.

## Проверка чека

| Суффикс метода | Позиционные параметры | Результат |
|---|---|---|
| `verifyReceipt` | `[receipt_hex: string]` | `ReceiptVerifyResult` |

После декодирования hex вход чека ограничен 128 KiB. `merkle_valid` и
`canonical` независимы: математически согласованный чек может ссылаться на
корень вне канонической цепи этой ноды.

## Методы внешнего майнинга

| Суффикс метода | Позиционные параметры | Результат |
|---|---|---|
| `getBlockTemplate` | `[miner_address: string]` | `BlockTemplateResponse` |
| `submitBlock` | `[template_id: string, nonce_hex: string]` | ID принятого блока |

Нода должна работать в режиме внешнего майнера. Пустой `miner_address`
использует адрес выплаты ноды; непустой принимается только при разрешённом
пользовательском адресе выплаты.

`nonce_hex` состоит ровно из 32 строчных hex-символов, кодирующих 16
байт в порядке от младшего к старшему. Шаблоны одноразовые и истекают через
30 секунд.

## Управление нодой

| Суффикс метода | Позиционные параметры | Результат |
|---|---|---|
| `stop` | `[]` | Строка состояния |

Первый вызов запрашивает корректное завершение. Повторные вызовы безопасны,
пока процесс закрывается.

## Методы кошелька

| Суффикс метода | Позиционные параметры | Результат |
|---|---|---|
| `walletStatus` | `[]` | `WalletStatus` |
| `walletGetAddress` | `[index: u32]` | Строка адреса |
| `walletGetBalance` | `[]` | `WalletBalance` |
| `walletListUtxos` | `[]` | `WalletUtxoInfo[]` |
| `walletHistory` | `[]` | `WalletHistoryEntry[]`, сначала старые |
| `walletReceipts` | `[page: u32, page_size: u32]` | `WalletReceiptsPage` |
| `walletMinedBlocks` | `[page: u32, page_size: u32]` | `WalletMinedBlocksPage` |
| `walletScan` | `[]` | `WalletScanResult` |
| `walletDiscoverAddresses` | `[max_additional: u32]` | `WalletAddressInfo[]` |
| `walletPlanSend` | `[to: string, amount: u64, fee: u64]` | `WalletSendPlan` |
| `walletSend` | `[to: string, amount: u64, fee: u64]` | `WalletSendResult` |
| `walletPlanConsolidation` | `[]` | `WalletConsolidationPlan` |
| `walletConsolidate` | `[slots: u32[], expected_fee: u64, expected_output: u64]` | `WalletConsolidationResult` |
| `walletExportReceipt` | `[txid: string]` | Чек в hex |
| `walletNextAddress` | `[]` | `WalletAddressInfo` |
| `walletListAddresses` | `[]` | `WalletAddressInfo[]` |
| `walletActiveAddress` | `[]` | `WalletAddressInfo` |
| `walletSetActiveAddress` | `[index: u32]` | `WalletAddressInfo` |

Суммы и комиссии выражены в μNOID. Нулевая комиссия в отправке или плане
запрашивает автоматический подбор.

Страницы чеков и добытых блоков начинаются с единицы и принимают размер 1–50.
`walletDiscoverAddresses` принимает 1–20 и останавливается на первом пустом
производном владельце.

`walletConsolidate` привязан к расчёту. Список слотов, комиссия и стоимость
выхода должны точно совпадать с последним планом; иначе вызов завершится
ошибкой и потребуется новый расчёт.

## Схемы ответов

В следующих схемах `?` обозначает необязательное поле, а `null` — явное
отсутствие значения в JSON.

### Цепь и `State`

```text
ChainInfo {
  height: u64
  best_hash: string
  difficulty_target: string
  active_slot_count: u64
  log_slots: u32
  circulating_supply_micronoid: decimal string
}

BlockHeaderInfo {
  height: u64
  hash: string
  prev_hash: string
  state_root: string
  tx_root: string
  timestamp: u64
  miner: string
  nonce_hex: string
  difficulty_target: string
  log_slots: u32
  active_slot_count: u64
  alloc_counter: u64
}

SlotInfo {
  slot_index: u32
  value: u64
  creation_id: u64
  owner: string
  empty: bool
}

TxInfo {
  tx_hash: string
  height: u64
  block_hash: string
  tx_position: u32
}
```

`circulating_supply_micronoid` — точная сумма стоимости всех UTXO в Live State,
выраженная в μNOID. Поле передаётся десятичной строкой, чтобы JSON не
терял точность.

```text
StateInfo {
  log_slots: u32
  capacity: u64
  active_slots: u64
  fill_pct: number
  slots_until_expand: i64
  expand_trigger_pct: u8
  log_slots_max: u32
  state_bytes: u64
  state_size_human: string
}

StateMapInfo {
  log_slots: u32
  bucket_capacity: u64
  live_counts: u64[]
}
```

`state_bytes` — канонически кодированные данные сегментов без страниц MDBX,
индексов и накладных расходов файловой системы.

### Подробности блока

```text
BlockDetailsInfo {
  header: BlockHeaderInfo
  retained: RetainedBlockInfo | null
}

RetainedBlockInfo {
  proof_class: string
  logical_transactions: u16
  user_pages: u16
  live_inputs: u16
  live_outputs: u16
  reward_micronoid: u64
  reward_noid: number
  total_fees_micronoid: decimal string
  block_bytes: u64
  history_step_bytes: u64
  bundle_bytes: u64
  transactions: BlockTransactionInfo[]
}
```

```text
BlockTransactionInfo {
  position: u16
  txid: string
  page_count: u16
  live_inputs: u16
  live_outputs: u16
  fee_micronoid: u64
  coinbase: bool
  development_payout: bool
  epoch_anchor: string
  input_owner: string | null
  input_sum_micronoid: decimal string
  output_sum_micronoid: decimal string
  page_hashes: string[]
  inputs: BlockTransactionInputInfo[]
  outputs: BlockTransactionOutputInfo[]
}

BlockTransactionInputInfo {
  page: u16
  lane: u8
  slot_index: u32
  amount_micronoid: u64
  creation_id: u64
}

BlockTransactionOutputInfo {
  page: u16
  lane: u8
  slot_index: u32
  amount_micronoid: u64
  owner: string
  creation_id: u64
}
```

```text
RecentTransactionsPage {
  page: u32
  page_size: u32
  total: usize
  total_pages: u32
  tip_height: u64
  retained_from_height: u64
  address: string | null
  transactions: RecentTransactionInfo[]
}

RecentTransactionInfo {
  height: u64
  block_hash: string
  timestamp: u64
  position: u16
  txid: string
  page_count: u16
  live_inputs: u16
  live_outputs: u16
  fee_micronoid: u64
  coinbase: bool
  development_payout: bool
  input_owner: string | null
  input_sum_micronoid: decimal string
  output_sum_micronoid: decimal string
  address_spent_micronoid: decimal string | null
  address_received_micronoid: decimal string | null
}
```

### Нода и майнинг

```text
MiningInfo {
  height: u64
  difficulty_bits: u32
  difficulty_target: string
  block_reward_micronoid: u64
  block_reward_noid: number
  active_slot_count: u64
}

NodeStatus {
  synced: bool
  sync_stage: "headers" | "state" | "tip"
  mining: bool
  mining_ready: bool
  mining_confirmed_peers: usize
  mining_required_peers: usize
  isolated_mining: bool
  backend: string
  available_threads: usize
  worker_threads: usize
}
```

`isolated_mining` — состояние ноды, запущенной в специальном операторском
контексте. В публичном развёртывании это поле нельзя использовать как
удалённое управление или свойство пира.

### Комиссии

```text
FeeEstimate {
  n_inputs: usize
  n_outputs: usize
  net_new_slots: u64
  active_slot_count: u64
  log_slots: u32
  fee_micronoid: u64
  breakdown: FeeBreakdownInfo
}

FeeBreakdownInfo {
  base: u64
  input: u64
  output: u64
  io: u64
  state_growth: u64
  required_total: u64
  relay_floor: u64
  relay_total: u64
  paid_total: u64
  burned: u64
  miner_claimable: u64
}
```

### Мемпул

```text
MempoolInfo {
  size: usize
  fee_floor: u64
  txs: MempoolTxInfo[]
}

MempoolStats {
  size: usize
  capacity: usize
  intent_bytes: u64
  max_intent_bytes: u64
  fee_floor: u64
}

MempoolTxInfo {
  tx_hash: string
  fee_micronoid: u64
  fee_rate: u64
  n_inputs: usize
  n_outputs: usize
  page_count: usize
  minimum_proof_class: string
  requires_b255_miner: bool
  admitted_height: u64
  has_authorization: bool
}
```

Ставка комиссии (`fee rate`) использует взвешенные единицы:

```text
inputs + outputs + 4 × net_new_slots
```

### Проверка адреса

```text
AddressInfo {
  valid: bool
  bech32: string | null
  hex: string | null
  error: string | null
}
```

Некорректный синтаксис адреса возвращается как `valid: false`, а не как
транспортная ошибка JSON-RPC.

### Идентичность и баланс кошелька

```text
WalletAddressInfo {
  address: string
  key_index: u32
  is_active: bool
}

WalletStatus {
  exists: bool
  address: string
  active_index: u32
  balance_micronoid: u64
  balance_noid: number
  utxo_count: usize
  address_count: u32
}

WalletBalance {
  balance_micronoid: u64
  balance_noid: number
  utxo_count: usize
  pending_outbound_micronoid: u64
  pending_incoming_micronoid: u64
  spendable_micronoid: u64
  spendable_noid: number
}
```

```text
WalletUtxoInfo {
  slot_index: u32
  value_micronoid: u64
  creation_id: u64
  value_noid: number
  address: string
  key_index: u32
  confirmed_height: u64
  reserved: bool
}

WalletHistoryEntry {
  tx_hash: string
  height: u64
  direction: "sent" | "received"
  is_coinbase: bool
  amount_micronoid: u64
  amount_noid: number
  peer_address: string | null
  timestamp: u64
  own_address: string | null
  own_key_index: u32 | null
}
```

### Отправка и консолидация кошелька

```text
WalletSendPlan {
  amount_micronoid: u64
  fee_micronoid: u64
  total_spend_micronoid: u64
  input_count: usize
  output_count: usize
  change_micronoid: u64
  fee_breakdown: FeeBreakdownInfo
}

WalletSendResult {
  txid: string
  amount_micronoid: u64
  fee_micronoid: u64
  input_count: usize
  output_count: usize
}
```

```text
WalletConsolidationPlan {
  input_value_micronoid: u64
  fee_micronoid: u64
  output_value_micronoid: u64
  balance_before_micronoid: u64
  balance_after_micronoid: u64
  input_count: usize
  untouched_count: usize
  remaining_count: usize
  freed_slots: usize
  selected_input_slots: u32[]
  fee_breakdown: FeeBreakdownInfo
}

WalletConsolidationResult {
  txid: string
  input_value_micronoid: u64
  fee_micronoid: u64
  output_value_micronoid: u64
  input_count: usize
  output_count: usize
  freed_slots: usize
}
```

### Сканирование и страницы кошелька

```text
WalletScanResult {
  found_utxos: usize
  balance_micronoid: u64
  balance_noid: number
  active_index: u32
  snapshot_height: u64
  snapshot_tip_hash: string
  snapshot_state_root: string
}
```

```text
WalletReceiptsPage {
  page: u32
  page_size: u32
  total: usize
  total_pages: u32
  receipts: WalletReceiptInfo[]
}

WalletReceiptInfo {
  txid: string
  height: u64
  timestamp: u64
  amount_micronoid: u64
  fee_micronoid: u64
  peer_address: string | null
  own_address: string | null
  own_key_index: u32 | null
  input_count: usize
  output_count: usize
  receipt_bytes: usize
}
```

```text
WalletMinedBlocksPage {
  page: u32
  page_size: u32
  total: usize
  total_pages: u32
  blocks: WalletMinedBlockInfo[]
}

WalletMinedBlockInfo {
  height: u64
  block_hash: string
  coinbase_txid: string
  timestamp: u64
  reward_micronoid: u64
  reward_noid: number
  payout_address: string
  payout_key_index: u32
  confirmations: u64
  full_block_available: bool
}
```

### Проверка чека

```text
ReceiptVerifyResult {
  merkle_valid: bool
  canonical: bool
  confirmed: bool
  error: string | null
  authenticated_summary?: ReceiptSummaryInfo
}

ReceiptSummaryInfo {
  txid: string
  claimed_height: u64
  confirmed_unix: u64
  tx_index: u16
  tx_count: u16
  fee_micronoid: u64
  inputs: ReceiptInputInfo[]
  outputs: ReceiptOutputInfo[]
}

ReceiptInputInfo {
  slot_index: u32
  owner: string
}

ReceiptOutputInfo {
  slot_index: u32
  amount_micronoid: u64
  owner: string
}
```

`authenticated_summary` присутствует только при корректном доказательстве
Merkle.

### Внешний шаблон

```text
BlockTemplateResponse {
  template_id: string
  pow_fields_hex: string
  nonce_field_index: usize
  difficulty_target_hex: string
  height: u64
  expires_in_seconds: u64
  n_txs: usize
  tx_input_counts?: usize[]
  tx_output_counts?: usize[]
  coinbase_value_micronoid: u64
  claimable_fees_micronoid: u64
}
```

`pow_fields_hex` содержит 16 последовательных 16-байтных little-endian полей.
Внешний вычислитель заменяет поле `nonce_field_index`, канонически равное 10.

## Ошибки

Ошибки парсинга, некорректного запроса, метода и параметров используют
стандартные коды JSON-RPC.

Ошибки приложения обычно используют:

```text
-32000
```

с человекочитаемым сообщением.

Одна ошибка планирования кошелька имеет стабильный машиночитаемый контракт:

```json
{
  "code": -32011,
  "message": "InputLimitExceeded",
  "data": {
    "max_inputs": 1020
  }
}
```

Это означает, что средств может быть достаточно, но в каноническом лимите
входов невозможно построить корректный платёж.

Клиент должен:

1. проверить HTTP-статус до декодирования JSON;
2. проверить объект JSON-RPC `error`;
3. обрабатывать документированные стабильные коды;
4. показывать остальные сообщения приложения оператору, не пытаясь разбирать
   их текст.
