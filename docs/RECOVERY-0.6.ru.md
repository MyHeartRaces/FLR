# FLR 0.6: сохранение состояния, восстановление и приёмка

> **Note (English): rolling back from 0.7 to the 0.6 controller on a router
> whose LAN is not 192.168.8.0/24** (for example the OpenWrt default 192.168.1.1).
>
> The 0.6 controller validates `/etc/flr-runtime/settings.json`
> strictly at start. Unless all three conditions below hold it refuses its
> settings, exits and is restarted by procd in a loop, and the boot guard
> blocks VPN-class LAN traffic until the file is fixed by hand:
>
> - `direct_proxy.bind` is exactly `192.168.8.1`;
> - every device profile in `options.profiles` is a host of 192.168.8.0/24
>   (`.2`–`.254`);
> - there is no `warm_reserve`, `routing_mode` or `tunnel_qos` key.
>
> 0.7 keeps the bind it read from disk (it binds the discovered LAN address
> only at runtime, and a direct proxy save in LuCI or the API stores only
> `enabled` and `port`) and never stores the default warm reserve, so the file
> normally stays acceptable. It stops being acceptable only after the owner
> set a non-default warm reserve or added a device profile on the current LAN,
> or if the stored bind was edited by hand.
>
> Check, read-only, as root on the router:
>
> ```sh
> jsonfilter -i /etc/flr-runtime/settings.json -e '@.direct_proxy.bind'  # must print 192.168.8.1
> jsonfilter -i /etc/flr-runtime/settings.json -e '@.options.profiles'   # nothing, or only 192.168.8.x keys
> jsonfilter -i /etc/flr-runtime/settings.json -e '@.warm_reserve'       # must print nothing
> jsonfilter -i /etc/flr-runtime/settings.json -e '@.routing_mode' -e '@.tunnel_qos'  # must print nothing
> ```
>
> Fix, only inside the approved rollback window (every step changes the live
> router), while 0.7 still runs:
>
> 1. Warm reserve back to its default, which removes the key:
>    `echo '{"operation":"settings","settings":{"warm_reserve":{"enabled":true,"interval_seconds":30}}}' | flr-controller api`
> 1a. Routing mode and tunnel queueing back to their defaults, which removes
>    the keys:
>    `echo '{"operation":"settings","settings":{"routing_mode":"split","tunnel_qos":{"enabled":false,"upload_kbit":0,"download_kbit":0}}}' | flr-controller api`
> 1b. Turn AWG endpoint roaming off on every AWG connection that has it
>    (the 0.6 controller rejects a registry with `roam_ports`/`roam_interval`):
>    `echo '{"operation":"connection-update","id":"<id>","metadata":{"roam_ports":"","roam_interval":0},"expected_generation":<n>}' | flr-controller api`
>    and check `jsonfilter -i /etc/flr-runtime/registry.json -e '@.connections[*].roam_ports'` prints nothing.
> 2. Remove each device profile outside 192.168.8.0/24 (that device then
>    follows the default policy, and its open connections are reset), e.g.
>    `echo '{"operation":"device","client":"192.168.1.20","value":"auto"}' | flr-controller api`
> 3. Only if the bind check fails; last, and with no LuCI or API change
>    afterwards (a later save writes the controller's in-memory bind back):
>    keep a copy with
>    `cp -p /etc/flr-runtime/settings.json /root/settings.json.before-rollback`,
>    then
>    `sed -i 's/"bind": "[^"]*"/"bind": "192.168.8.1"/' /etc/flr-runtime/settings.json`
>    (`direct_proxy.bind` is the only `bind` key in the file),
>    `chmod 0600 /etc/flr-runtime/settings.json`, and repeat the checks.
>
> If 0.6 is already running and refusing the file, apply the same `sed` and
> `chmod`, and remove a `warm_reserve` object or out-of-LAN profile entries
> with an editor, keeping the JSON valid and the file root-owned 0600. procd
> restarts the controller within seconds; otherwise run
> `/etc/init.d/flr-runtime restart`.

Это офлайн-подготовка. Команды ниже предназначены для **отдельно разрешённого
этапа на устройстве**. Сейчас роутер и VPS не опрашивались; свежая копия,
физический вход в U-Boot и загрузка нового образа не проверены.

## Что сохранить

Единственный список FLR — `packages/flr-runtime/files/flr-runtime.keep`;
пакет устанавливает его как `/lib/upgrade/keep.d/flr-runtime`.

| Файл внутри `/etc/flr-runtime` | Назначение |
| --- | --- |
| `settings.json` | Включение VPN, настройки, политика устройств и выбранный профиль |
| `profiles.json` | Старый приватный v1-реестр, источник миграции; пустой реестр также сохраняется |
| `registry.json` | Актуальный v2-реестр подключений: ID, revision, конфиги и метаданные; обязателен вместе с settings v2 |
| `connection-state.json`, `.connection-{old,new}-{registry,settings}.json` | Marker и четыре stage-файла согласованной публикации registry/settings; нужны для восстановления прерванной транзакции |
| `migration-v2.json`, `.registry-v2.json`, `.settings-v2.json` | Подготовленная миграция v1→v2; marker восстанавливается только вместе с обеими стадиями |
| `migration-v1/manifest.json`, `migration-v1/{settings.json,profiles.json,primary-awg.conf,gecko.json,vless.json}` | Точный приватный снимок исходников; сохраняются только явно перечисленные существующие файлы |
| `primary-awg.conf` | Приватный исходник основного AWG |
| `gecko.json`, `vless.json` | Старые самостоятельные профили, источник первой миграции |
| `backup/network`, `backup/firewall`, `backup/dhcp` | Исходная конфигурация до FLR для штатного rollback |
| `boot-guard.nft` | Исходник защитного nft ruleset и доказательство владения |
| `rollback.pending` | Незавершённая активация; после перезагрузки требует восстановления |
| `rollback.disabled` | Долговечное намерение отката: после восстановления checkpoints отключает VPN, direct proxy и direct bypass; удаляется только после сохранения выключенных настроек |

Каталог целиком не включается: неизвестные секреты требуют отдельного решения.
`manual-games.json` и `direct-session.json` — устаревшие временные состояния;
их не восстанавливаем. `/var/run/flr-runtime` содержит PID, сокеты, lock,
owner/status, WAN-pin journal и сгенерированные конфиги процессов; они заново
создаются в новом boot. Политика FLR в образе остаётся пакетной версией.
Текущие `/etc/config/{network,firewall,dhcp}` сохраняются штатным sysupgrade;
они отличаются от **до-FLR** снимков в `backup/`.

Состояние — обычные непустые root-owned файлы 0600, каталоги FLR/backup — 0700.
Файловый список sysupgrade может не включать режимы родительских каталогов:
перед recovery штатный запуск проверяет реальные каталоги и нормализует эти
каталоги FLR, backup и migration-v1 до 0700. Ссылки в пути отвергаются, неизвестные файлы не chmod-ятся.
Небезопасный режим самих файлов автоматически не исправляется.

Первый startup без реестра импортирует валидные старые outbounds, убирая
только прежние `bind_interface`/`routing_mark`. Источники не удаляются.
Ошибочный, публичный или symlink-источник останавливает миграцию без записи
реестра; после исправления возможен повтор. Уже существующий реестр, включая
пустой, никогда не пополняется из старых файлов. Отсутствующие настройки дают
выключенный VPN; валидные настройки 0.5 сохраняют прежнее включение.
Наличие pending от прошлого boot означает восстановление до запуска VPN,
а не автоматическое подтверждение нового образа.

## Первое обновление 0.5 → 0.6

Новый keep.d начинает действовать только **после** установки нового пакета.
Архив первого обновления формирует старая прошивка. Источник поведения:
[OpenWrt v25.12.5 sysupgrade](https://raw.githubusercontent.com/openwrt/openwrt/v25.12.5/package/base-files/files/sbin/sysupgrade).
Он читает sysupgrade.conf и keep.d; `-b` создаёт архив, `-l` показывает список,
`-T` проверяет образ, а `-f` задаёт архив для восстановления. Проверка `-T`
не подтверждает полноценность содержимого FLR или реальное восстановление.

1. Подготовить проводной компьютер, стабильное питание, окно простоя и
   резервный доступ в интернет. Сохранить офлайн новый sysupgrade, его
   SHA256SUMS/verification/source provenance, предыдущий рабочий sysupgrade
   и отдельный совместимый U-Boot-файл из следующего раздела.
2. После разрешения пользователя получить **свежую** приватную полную копию
   конфигурации и записать дату/boot-id/модель/текущую версию. Старые копии свежими не считаются.
3. Передать точный `flr-runtime.keep` из проверенного source commit в
   `/tmp/flr-runtime.keep` старого роутера. Проверить его SHA256 и все явно перечисленные пути.
   Не подменять список каталогом `/etc/flr-runtime/`.
4. На старом роутере, после отдельного разрешения на изменения:

   ```sh
   set -eu
   umask 077
   [ -d /etc/flr-runtime ] && [ ! -L /etc/flr-runtime ]
   [ "$(stat -c %a /etc/flr-runtime)" = 700 ]
   if [ -e /etc/flr-runtime/backup ] || [ -L /etc/flr-runtime/backup ]; then
     [ -d /etc/flr-runtime/backup ] && [ ! -L /etc/flr-runtime/backup ]
     [ "$(stat -c %a /etc/flr-runtime/backup)" = 700 ]
   fi
   cp /etc/sysupgrade.conf /tmp/sysupgrade.conf.before-flr
   cat /tmp/flr-runtime.keep >> /etc/sysupgrade.conf
   sysupgrade -l > /tmp/first-upgrade.files
   : > /tmp/flr-state.sha256
   while IFS= read -r path; do
     case "$path" in ''|'#'*) continue ;; esac
     if [ -e "$path" ] || [ -L "$path" ]; then
       [ -f "$path" ] && [ ! -L "$path" ] || exit 1
       [ "$(stat -c %a "$path")" = 600 ] || exit 1
       sha256sum "$path" >> /tmp/flr-state.sha256 || exit 1
     fi
   done < /tmp/flr-runtime.keep
   sysupgrade -b /tmp/first-upgrade.tgz
   chmod 600 /tmp/first-upgrade.tgz /tmp/flr-state.sha256
   sha256sum /tmp/first-upgrade.tgz
   ```

   Сохранить отдельно прежний sysupgrade.conf. Если он отсутствует, сначала
   выяснить штатное состояние системы; не продолжать скрипт с ошибкой `cp`.
   Проверить приватные родительские каталоги и полный `first-upgrade.files`;
   убедиться, что остальные требуемые системные настройки входят в копию.
   Перед inventory и архивом завершить активные операции управления и остановить
   службу FLR в согласованном окне простоя. Это прерывает VPN-сессии, зато не
   позволяет registry/settings измениться между чтениями sysupgrade. При
   незавершённом checkpoint сохраняются marker и все его зависимости; неполный
   архив отклоняется preflight. Не изменять настройки/профили между inventory,
   архивом и обновлением.
   Временные файлы содержат секреты и остаются приватными.
5. Скачать архив, manifest и список в приватный каталог компьютера; сверить
   SHA256 с роутером. Офлайн, из репозитория:

   ```sh
   chmod 600 '<private>/first-upgrade.tgz'
   python3 ci/upgrade_archive.py '<private>/first-upgrade.tgz' \
     --expected '<private>/flr-state.sha256' --require-state \
     > '<private>/first-upgrade-preflight.json'
   ```

   Preflight ничего не извлекает и не печатает содержимое. Он проверяет
   пути, ссылки/special files, дубликаты, режимы FLR, ограничение размеров,
   JSON-синтаксис, полный recovery-снимок и точные хеши инвентаря. Для settings v2
   обязателен registry.json; для pending v2 checkpoint — полный комплект stage
   и migration snapshot файлов. Семантику и хеши checkpoint проверяет runtime.
   Ссылки отклоняются во всём архиве: если штатная копия содержит ссылку,
   остановиться и отдельно проверить её происхождение/необходимость, а не
   обходить проверку. Семантику профилей/AWG/settings проверяет Go runtime.
   Отсутствующий FLR допустим только для намеренно чистой установки; для
   сохранения настроенного устройства обязателен `--require-state` и manifest.
6. После успешного preflight на устройстве выполнить `sysupgrade -T -f
   /tmp/first-upgrade.tgz /tmp/candidate-sysupgrade.bin`. Проверить модель,
   совместимость и хеш загруженного файла. Ошибка — остановка; `-F`, `-n`,
   ignore-compat и raw partition flashing здесь не применяются.
7. Только при отдельном разрешении прошивки: `sysupgrade -f
   /tmp/first-upgrade.tgz /tmp/candidate-sysupgrade.bin`. После загрузки
   проверить восстановленные пути/0600, миграцию и recovery **до** подтверждения
   активации. Не доверять одному наличию веб-интерфейса: при установке build-7
   исторически архив `-f` автоматически не восстановился, применялся вручную.
   Если настройки не восстановились, остановить приёмку и диагностировать
   офлайн-копию; ручное восстановление — отдельное согласованное действие.

Если этап прерван **до прошивки**, вернуть исходный sysupgrade.conf из копии
именно этой попытки. Только после подтверждённого скачивания приватных файлов
на компьютер убрать временные копии с роутера; локальный recovery-комплект
сохранить. Pending/boot guard при этом не удаляются:

```sh
set -eu
[ -f /tmp/sysupgrade.conf.before-flr ]
cp /tmp/sysupgrade.conf.before-flr /etc/sysupgrade.conf
rm -f /tmp/sysupgrade.conf.before-flr /tmp/flr-runtime.keep \
  /tmp/first-upgrade.files /tmp/flr-state.sha256 /tmp/first-upgrade.tgz
```

## Firmware recovery и штатный rollback

`flr-rollback` восстанавливает network/firewall/dhcp при рабочем ядре/rootfs.
Это не восстановление прошивки. На ошибке сохраняются pending/owner и исходник
boot guard; boot table удаляется только после успешных проверенных reload.
Повторяет операцию recovery, а не удаление marker вручную.

Держите офлайн предыдущий рабочий sysupgrade-образ (имя файла не подтверждает
совместимость с U-Boot) и официальный образ GL-MT6000 с
[страницы производителя](https://dl.gl-inet.com/router/mt6000/stable); хеш
скачанного файла сверяйте с опубликованным. Физическое восстановление конкретного
экземпляра **UNTESTED**. Держите файлы офлайн в `<private>/recovery/`.

Будущий физический этап по [инструкции GL.iNet](https://docs.gl-inet.com/router/en/4/faq/debrick/):
выключить питание, подключить компьютер к LAN2/3/4, отключить остальные порты;
LAN1 не использовать. Удерживая Reset, включить питание; у Flint 2 синий LED
мигает шесть раз, затем белый. На компьютере задать 192.168.1.2/24 и открыть
`http://192.168.1.1`. Перед загрузкой проверить модель и выбранный совместимый
файл. Во время восстановления питание не отключать; настройки будут стёрты.
Затем вернуть DHCP компьютера и отдельно восстановить проверенную конфигурацию.
Если U-Boot UI недоступен или модель/файл не подтверждены — остановиться.
Bootloader/FIP/GPT и сырые дампы разделов не прошиваются в этом плане.

## Порядок приёмки

| Порядок | Проверка и stop-критерий | Состояние |
| --- | --- | --- |
| 1 | Свежий архив, inventory, offline preflight; несовпадение/неполнота → stop | UNTESTED на устройстве |
| 2 | Физический доступ к recovery UI и совместимый офлайн-файл; UI недоступен → stop | Файл проверен, U-Boot UNTESTED |
| 3 | Sysupgrade -T и точный хеш/модель; ошибка → stop | UNTESTED |
| 4 | Первый boot, файлы/режимы, миграция; pending вызывает recovery до VPN | UNTESTED |
| 5 | Чистая установка: VPN выключен, административный доступ и direct defaults | UNTESTED |
| 6 | Один проводной тестовый клиент: DNS, IPv4/IPv6 guards, AWG, импорт, смена профиля | UNTESTED |
| 7 | Отказ native/reload, сохранение guards/markers и успешный retry; нет fail-open | UNTESTED kernel/device |
| 8 | Явное подтверждение guarded activation до истечения 180 секунд; при ошибке rollback | UNTESTED |
| 9 | AWG недоступен либо устойчиво деградирует: HY2 той же явно заданной группы → другие HY2 → другие семейства по настроенному порядку. Неверный порядок или прямой WAN вместо резерва → stop | UNTESTED |
| 10 | Квалифицированное восстановление AWG по двум независимым целям проверки и обоим протоколам, полный интервал и число наблюдений; affinity, DNS и запрет WAN-утечек. Ранний возврат, устаревшие flows, DNS-утечка или fail-open → stop | UNTESTED |
| 11 | Постоянный direct SOCKS: TCP, UDP ASSOCIATE, только LAN, нужный WAN, сохранение после перезагрузки. Доступ с WAN, неверный egress или потеря UDP → stop | UNTESTED |
| 12 | qBittorrent: загрузка и раздача на Mac/PC плюс входящие/исходящие соединения после переназначения класса в обе стороны; устройство direct имеет стабильный DHCP/IP и ожидаемый выход через WAN. Старые NAT/affinity, переход чужого устройства, неожиданный выход через VPS либо WAN для VPN-класса → stop | UNTESTED |
| 13 | Перезагрузка/пауза проверок и повторный startup, затем домашние устройства; отсутствие бесконечного recovery, лишних процессов и смены принятого профиля. Потеря управления, некорректная квалификация или недоступность LAN → stop | UNTESTED |
| 14 | Отдельные замеры throughput, CPU/RAM, loaded ping и продолжительный soak при обычной домашней нагрузке; заранее записать допустимые значения и длительность. Регрессия, OOM, рост числа процессов или повторные native timeout → stop | UNTESTED |
| 15 | Zapret проверяется последним; остаётся выключенным до отдельной ISP-приёмки YouTube, Discord voice, Telegram, TCP/QUIC, исключения VPN и регрессии игр. Любая неподтверждённая функция/утечка → выключить и stop | UNTESTED |

Порядок HY2, критерии деградации/квалификации и ограничения фиксированного
bypass описаны в [ROUTER-0.6.ru.md](ROUTER-0.6.ru.md); API и параметры —
[ROUTER-API.md](ROUTER-API.md). Discord voice и произвольный Telegram UDP
не становятся поддержанными только от включения пресета UDP 443.
Ни синтетические тесты, ни статическая проверка образа не меняют эти статусы.
