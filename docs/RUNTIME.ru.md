# Постоянный VPN FLR

Инструкция для установленного Flint 2, OpenWrt 25.12 и основного сервера
(`203.0.113.10`, `vpn.example.com`, DNS only). Go и новые пакеты на рабочей
станции не требуются: ARM64 controller собирается в GitHub Actions.

## Что работает

Один `flr-controller` управляет маршрутами, marks, DNS и выбором канала. AWG3.1
работает в ядре; два независимых sing-box процесса обслуживают Gecko и VLESS.

| Трафик | Автоматический порядок | При отказе всех каналов |
|---|---|---|
| Обычный VPN | AWG → Gecko → VLESS | Закрыт, WAN fallback отсутствует |
| Игры | AWG → Gecko | Закрыт; VLESS разрешается вручную |
| Direct-списки приватного overlay | WAN | Продолжает работать при работающем контроллере |
| Локальная сеть | Локальные маршруты | Сохраняется |

Списки direct и VPN-сервисов задаёт приватный overlay политики (см.
`policy/README.md`); без него всё, кроме локальных адресов, идёт через VPN.
Обязательные VPN-исключения имеют приоритет над direct. Общий CDN-IP
при живом VPN binding остаётся VPN. Неизвестные игровые IP определяются игровым
профилем устройства; доменных списков для всех игровых серверов недостаточно.

Cloudflare Standard → Quad9 Unfiltered DoH передаётся внутри выбранного VPN.
Для direct используется WAN DHCP DNS, для `.lan` — локальный dnsmasq1053.
Кеши разных представлений разделены. LAN TCP/UDP53 перехватывается роутером;
клиентский DoH не расшифровывается. LAN IPv6 forwarding выключен.

## Повседневные команды

Все команды ниже выполняются **на Flint по SSH**, с правами root:

```sh
flr-controller status --json
flr-controller validate
flr-controller games auto
flr-controller games vless
```

`games vless` вручную закрепляет игры за VLESS, пока он исправен. Если VLESS
недоступен, игры закрыты; возврат к AWG/Gecko — `games auto`. Обычный VPN имеет
свой независимый выбор. Изменение выбора применяется к новым соединениям.

Проверка health идёт каждые5s:3 неудачных раунда выключают канал, исчезнувший
интерфейс выключает его сразу, восстановление требует60s успешных проб. Проверяются
HTTPS/TCP и UDP; `round_duration_ns` в status — длительность всего раунда,
не ICMP ping. Проблема одного DNS upstream не перезапускает транспорт.

Рабочие соединения остаются на прежнем исправном канале. Соединения неисправного
канала удаляются по его ct mark; общего conntrack flush нет. Смена внешнего IP
при failover может оборвать игровую сессию — автоматизация не переносит её состояние.

## Профили устройств

Укажите действительный адрес устройства из DHCP leases. Для стабильного адреса
создайте статическую DHCP lease в LuCI.

```sh
flr-controller profile 192.168.8.126 games
flr-controller profile 192.168.8.126 direct
flr-controller profile 192.168.8.126 general
flr-controller profile 192.168.8.126 auto
```

`games` отправляет неизвестные игровые IP через игровой канал, сохраняя обязательные
VPN-исключения и direct-правила overlay. `direct` и `general` — явный выбор всего
публичного IPv4-трафика устройства, выше доменных правил. `auto` снимает профиль.
Профили хранятся в root-only settings.json и переживают reboot. Они привязаны к IP,
поэтому при смене DHCP адреса профиль надо переназначить. Новые DNS-запросы получают
соответствующее представление; уже закешированные клиентом адреса/старые соединения
могут сохраняться до истечения TTL или переподключения приложения.

## Временный direct для браузера

```sh
flr-controller direct-session --client 192.168.8.126 --ttl 15m
flr-controller direct-session stop
```

Максимум15m, одна сессия одновременно. SOCKS5 слушает `192.168.8.1:1088`, только
для выбранного IP и текущего MAC из действительной DHCP lease. На WAN он закрыт.
Отдельный worker использует собственный WAN DNS/cache. TTL, остановка, рестарт
контроллера и изменение DHCP IP/MAC закрывают worker; после reboot сессия не
восстанавливается. Удаляются только соединения с session mark.

В FoxyProxy создайте SOCKS5 `192.168.8.1`, порт1088, без логина/пароля. Включите
DNS через SOCKS, разрешите профиль только нужным доменам или отдельному
контейнеру Firefox. Для оплаты проще временно включить его для всей отдельной
вкладки/профиля браузера: у checkout могут быть дополнительные домены. Проверьте
внешний IP через этот профиль перед оплатой. Сам платёж выполняете вы.

Worker поддерживает TCP CONNECT, включая HTTPS; UDP ASSOCIATE и IPv6 отклоняются.
Для полного direct TCP+UDP устройства используйте профиль `direct`. На компьютере
с отдельным VPN расширение должно уметь обратиться к LAN Flint; системный VPN,
отключающий локальную сеть, потребуется настроить отдельно. При отключении proxy
Firefox не должен автоматически повторять ту же оплату другим профилем.

## Установка/обновление controller

Используйте binary из успешного workflow **Flint runtime** ветки с проверенным
кодом. Артефакт содержит только `flr-controller` и `SHA256SUMS`; проверьте hash.
Артефакт образа сам по себе новый runtime не содержит. Обновлять OpenWrt или
пакеты для этой установки не нужно.

На рабочей станции из каталога распакованного runtime artifact:

```sh
shasum -a 256 -c SHA256SUMS
scp flr-controller root@<адрес роутера>:/tmp/flr-controller
```

Перед первой установкой скопируйте также `runtime/openwrt/flr-runtime.init`,
`flr-proxies.init`, `flr-runtime.rollback`, `flr-runtime.hotplug` соответственно
в `/etc/init.d/flr-runtime`, `/etc/init.d/flr-proxies`, `/usr/sbin/flr-rollback`,
`/etc/hotplug.d/iface/95-flr-runtime`, mode755. Политика образа —
`/usr/share/flint-vpn/policy`, приватный overlay — `/etc/flr-runtime/policy`. Private server profiles передаются отдельно, mode600:
`awg.conf`, `sing-box-outbounds.json` в `/etc/flint-vpn/clients/main-server`.
В GitHub они не загружаются. Ключ HeaderProtectionKey у AWG3.1 обязателен.

На Flint:

```sh
chmod 755 /tmp/flr-controller
/tmp/flr-controller --version
/tmp/flr-controller validate
mv /tmp/flr-controller /usr/sbin/flr-controller
flr-controller backup --backup /etc/flr-runtime/backup
flr-controller prepare --profiles /etc/flint-vpn/clients/main-server
flr-controller apply --test-client 192.168.8.126
```

Этот порядок с `apply` относится только к исходному состоянию 0.5 до миграции.
В 0.6 с v2-реестром или незавершённой миграцией команда отвергается **до изменений сети**:
импорт, выбор подключения и guarded activation выполняются через страницу «Прокси».
Rollback сохраняет подключения и ручной выбор, но отключает VPN, direct proxy и
direct bypass после завершения восстановления checkpoints. Настройки не удаляются.

Этот legacy `apply` не является порядком установки домашнего режима 0.6.
Он требует один тестовый LAN IP, включает180s rollback guard и DNS1054 только
для него. В 0.6 команда `enable-home` выведена из эксплуатации и отвергается
до чтения policy/settings и изменений сети: прежний прямой путь записи мог
перезаписать параллельное изменение v2-реестра или настроек.

Для домашнего режима 0.6 импортируйте подключения на странице «Прокси» и
используйте её guarded activation. Она сериализована с изменениями настроек,
переносит dnsmasq на1053 и broker на53, устанавливает boot guard и включает
службу на boot. После проверки SSH/LuCI, WAN/direct и фактического VPN-пути
подтвердите активацию в «Обзоре». Не подтверждайте guard заранее и не удаляйте
backup: неподтверждённая активация откатывается через180s, reboot с pending
тоже вызывает восстановление. Старые немаркированные WAN-соединения после
включения домашнего режима могут потребовать переподключения приложений.

Обновление уже работающего controller после проверки артефакта: замените binary,
запустите `flr-rollback arm`, `/etc/init.d/flr-runtime restart`, проверьте сеть и
подтвердите guard. Рестарт очищает DNS/cache/maps и закрывает временный direct,
но не перезапускает исправные sing-box процессы. При ошибке маршрутов контроллер
оставляет защиту активной, показывает last_error и повторяет проверку.

## Откат и диагностика

```sh
flr-controller rollback --backup /etc/flr-runtime/backup
```

Откат сначала проверяет наличие трёх приватных непустых backup-файлов. Он выключает
FLR services, удаляет свои nft/rules/routes и восстанавливает исходные network,
firewall, DHCP. Это возврат к обычному интернету стенда, а не downgrade прошивки.
После остановки runtime команда удерживает singleton, private admin и rollback
generation lock до конца восстановления. Если уже выполняется offline activation,
откат возвращает busy: дождитесь завершения операции и повторите команду. Ручной
откат не удаляет token/guard новой активации. Явный `--backup` сохраняется; каталог
и все три файла должны пройти приватную проверку до остановки службы.
Bootloader/Web Recovery/factory/GPT не меняются.

```sh
flr-controller status --json
fw4 check
ip -4 rule
ip -4 route show table 770
ip -4 route show table 771
ip -4 route show table 772
nft list table inet flr
logread | tail -60
awg show flr_awg latest-handshakes
```

Не выводите полный `awg show`, UCI network или transport configs в публичный лог:
AWG3.1 может показывать HeaderProtectionKey. Status не содержит VPN auth/keys/UUID.

## Ограничения текущего этапа

Управление CLI; отдельного приложения FLR в LuCI пока нет. WAN настраивается
владельцем (DHCP или профиль провайдера) на eth1; креды провайдера в образ не входят.

SS2022+ShadowTLSv3 остаётся будущим target; zapret2 выключен. Три транспорта имеют
один IP/VPS: отказ сервера или блокировка этого IP отключит все три. Для независимого
резерва нужен второй endpoint. Измеренные результаты и границы проверки смотрите
в deployment report; длительная гарантия доступности и1Gbps этим этапом не даются.
