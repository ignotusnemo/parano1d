# Сборка из исходного кода

Рабочее пространство использует Rust 2021 и зафиксированную версию Rust `1.96.0`.
Нативные зависимости нужны для MDBX, кода доказательств и упаковки GUI.

## Требования к машине

На всех платформах необходимы:

- зафиксированный набор инструментов Rust с `rustfmt`;
- нативный компилятор C/C++;
- CMake;
- libclang;
- Git.

На Debian или Ubuntu:

```sh
sudo apt update
sudo apt install --no-install-recommends \
  build-essential clang libclang-dev cmake pkg-config
```

Для Linux-пакета GUI также нужны `appstreamcli` и `dpkg-deb`. Релизная
упаковка Windows использует Inno Setup 6, macOS — стандартные инструменты
`codesign`, `iconutil` и `hdiutil`.

Файл `rust-toolchain.toml` в репозитории автоматически выбирает компилятор:

```sh
rustup show active-toolchain
rustc --version
cargo --version
```

## Проверка рабочего пространства

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
```

Сборка обычных бинарников для разработки:

```sh
cargo build --locked \
  -p noid_node \
  -p noid-extminer \
  -p noid_gui \
  --bins
```

Такие исполняемые файлы подходят для проверки разбора данных, интерфейса и
тестовых путей, не создающих блоки. Для производства блоков бинарнику релизной
сборки нужен описанный ниже аутентифицированный пакет матриц
`HistoryStep`.

## Материалы доказательств

Сборка для mainnet аутентифицирует матрицы Small, Large и Native по одному
закреплённому банку. Используйте пакеты mainnet и независимо проверенные хеши
для собираемых исходников. Храните полученные артефакты вне `target/`.

### Банк матриц

Пакет трёх классов имеет следующую структуру и закрепление:

```text
v21-runtime-metadata.bin
v21-small.field-r1cs.zst
v21-large.field-r1cs.zst
v21-native.field-r1cs.zst
```

```text
NOID_V21_RELEASE_BANK=6c280ae869afc25e31d46d73b42870512991b78c9498bc7e5ef939bc07e5ed5e
```

Хеш связывает матрицы, интерпретатор, бюджеты и расписание консенсуса.
У пакета изолированной тестовой сети другой идентификатор. Сборка проверяет
метаданные и каждую матрицу перед встраиванием.

### Материалы проверки происхождения

Синхронизация также аутентифицирует сохранённое происхождение цепочки.
Входы поставляются отдельными каталогами истории, матриц и ключей предобработки:

```text
v1/history-step.runtime
v2-runtime-metadata.bin
v2-small.field-r1cs.zst
v2-large.field-r1cs.zst
class-0.key
class-1.key
```

```text
NOID_V2_RELEASE_BANK=c2a6df736b0d0da22e285b6930b11cf44b520d65b52c7dfe78f44fe0cd48e76e
NOID_RETIREMENT_KEY_0_PIN=<authenticated-key-0-digest>
NOID_RETIREMENT_KEY_1_PIN=<authenticated-key-1-digest>
```

Используйте независимо пересчитанные хеши ключей. Файл закреплений читается
как данные. [Запись банка происхождения](https://git.parano1d.org/ignotusnemo/parano1d/src/branch/v2/research/v2_feasibility/results/2026-09-25-common-input-budget/REPORT.md)
указывает матрицы и процедуру их аутентификации.

### Расчёт ресурсов проверки происхождения

Команда учитывает сохранённый банк происхождения, его ключи предобработки
и соответствующие рекурсивные редукции:

```sh
cargo build --release --locked -p bench_prover --bin noid_v2_soundness
target/release/noid_v2_soundness \
  LEGACY_METADATA LEGACY_METADATA_PIN V2_METADATA V2_BANK_PIN \
  CLASS_0_KEY CLASS_0_KEY_PIN CLASS_1_KEY CLASS_1_KEY_PIN
```

[Вывод](https://git.parano1d.org/ignotusnemo/parano1d/src/branch/v2/noid_soundness/docs/v2-retirement.md)
задаёт точные входы и предпосылки этого расчёта.

## Нативные поставки

Перед упаковкой выполните проверки исходников и [квалификацию](testing.md):

```sh
./scripts/build_release.sh \
  --pack ../parano1d-artifacts/history-step-pack-v1 \
  --v2-pack PATH_TO_FROZEN_V2_PACK \
  --v2-pins PATH_TO_REVIEWED_PIN_FILE \
  --v21-pack PATH_TO_FROZEN_V21_PACK \
  --v21-pins PATH_TO_REVIEWED_V21_PIN_FILE \
  --retirement-keys PATH_TO_AUTHENTICATED_KEYS \
  --retired-history

cat target/release-builds/LAST_RELEASE
```

Скрипт проверяет структуру входов и хеши, встраивает аутентифицированные
материалы, отклоняет другое расписание, собирает Core и GUI, проверяет запуск
бинарников, состав пакетов и SHA-256. Полный набор тестов протокола запускается
отдельно. `proof-pins.env` фиксирует встроенные идентификаторы.
`--output PATH` выбирает новый каталог результата.

Для mainnet используйте `--retired-history`. Узел получает сертификат
выбранного происхождения по P2P и проверяет его по независимо закреплённым
ключам предобработки. Бинарник включает банк трёх классов, сохранённый банк
происхождения и их метаданные. Исторический входной архив содержит
`v1/history-step.runtime`, `pins.env` и их `SHA256SUMS`.

Публикатор выбирает этот профиль по умолчанию. `--with-legacy-history`
встраивает полные исторические матрицы для воспроизведения из исходников.
Синхронизация выбирает аутентифицированное отношение по расписанию блока.

## Переносимые бинарники

Релизы x86-64 собираются для переносимого базового набора инструкций. После
проверки машины при запуске выбирается `pclmul`, `avx2+vpclmul` или
`avx512bw+vpclmul`. На ARM64 выбирается `neon+pmull`.

Не собирайте официальные артефакты с `target-cpu=native`: бинарник начнёт
зависеть от машины сборки ещё до проверки оборудования при запуске.

## Воспроизводимый архив

На системах с GNU tar переменная `SOURCE_DATE_EPOCH` управляет временными
метками файлов и по умолчанию равна нулю. Состав архива Core фиксирован:

```text
README.txt
CONTRACTS.md
LICENSE
NOTICE
parano1d
parano1d-cli
parano1d-miner
```

GUI-пакет содержит только приложение и встроенную в него ноду. Операторский CLI и
инструменты внешнего майнинга в него не входят.
