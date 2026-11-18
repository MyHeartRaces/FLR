# FLR: базовая сборка основного VPS

Руководство описывает типовую сборку основного сервера (Debian 13, cloud kernel).
Адреса и имена ниже — примеры: `203.0.113.10`, `vpn.example.com`,
`*.pace.example.com`. Секреты и реальные конфиги хранятся в приватном месте,
не в этом репозитории. Обновление движков на сервере — `server/engine-update`
и `ENGINE-UPDATES.md`.

## Доступ и службы

```sh
ssh -i ~/.ssh/<ключ> -o IdentitiesOnly=yes <admin>@203.0.113.10
```

Root SSH, password и keyboard-interactive authentication выключены. Административный
пользователь имеет sudo. SSH 22 открыт для ключевого управления. Forwarding,
agent forwarding, X11 и tunnels запрещены. Новый ключевой вход проверяется после
hardening и после применения firewall.

| Компонент | Версия | Порт/служба |
|---|---|---|
| AWG kernel module (DKMS) | закреплён по tag и commit | UDP 51820, `awg-quick@awg0` |
| AWG tools | закреплены по tag и commit | `/usr/local/bin/awg` |
| Hysteria2 (Gecko) | upstream stable, compat-lock | UDP 443 |
| Cover site (Caddy) | пакет Debian | TCP 80/443, собственный сертификат |
| Запасной AWG `awg1` | как основной, другой профиль обфускации | отдельный UDP-порт |
| Port hopping Hysteria | диапазон UDP, redirect на 443 | таблица nftables |

Binaries скачиваются с официальных GitHub releases, SHA256 сверяется с release
asset digest. DKMS собирает AWG для установленного cloud kernel; перед kernel
upgrade проверьте DKMS для нового ядра (cloud kernel headers должны быть
установлены). `HeaderProtectionKey` обязателен и совпадает у client/server; не
печатайте `awg show` целиком, поскольку upstream показывает этот параметр даже
при скрытом PrivateKey.

Hysteria использует собственный wildcard-сертификат (ACME DNS-01), отдельный от
сертификата cover-сайта; профили роутера используют фиксированное имя под ним.
Client TLS verification включена, `insecure=false`; endpoint задан IPv4 отдельно
от SNI. Hysteria маскируется под cover-сайт; на неавторизованные UDP-пробы сервер
молчит.

## Проверка состояния

```sh
sudo systemctl is-active nftables awg-quick@awg0 hysteria caddy
sudo systemctl is-enabled nftables awg-quick@awg0 hysteria caddy
sudo sshd -t
sudo nft -c -f /etc/nftables.conf
sudo dkms status
sudo awg show awg0 latest-handshakes
sudo awg show awg0 transfer
```

Не публиковать конфиги, credentials, server/client private keys или auth strings.

## Конфигурация

- `/etc/amnezia/amneziawg/awg0.conf`: адрес туннеля, MTU около 1380, один peer на роутер.
- Конфиги Hysteria и секреты: отдельный service user, root-owned, mode 640 с service group.
- `/etc/nftables.conf`: INPUT/FORWARD default drop; открыты SSH 22/TCP, 80 и 443/TCP
  (cover-сайт), 443/UDP (Hysteria), порт AWG/UDP, ICMP и IPv6 ND/PMTU.
- NAT только для подсети туннеля; private/metadata destinations запрещены.
- `/etc/sysctl.d`: IPv4 forwarding, UDP socket maxima 32 MiB.
- LLMNR/mDNS systemd-resolved отключены; публичного SOCKS/DNS/iperf listener нет.
- Перед применением firewall удалённо используйте rollback timer (например, 180 s),
  затем проверьте новый ключевой вход и отмените timer.

Службы включены на boot. Обновления binaries идут через compat-locked updater.

## Проверки приёмки

Клиентские тесты запускаются на роутере через его обычный WAN, а не с рабочей
станции (она может быть за другим VPN). Каждый канал должен пройти устойчивый
HTTPS-трансфер и UDP через туннель. Handshake и несколько ping — не приёмка.
Временные benchmark listeners и правила удаляются после тестов.

## Заметки по облачным образам

Если провайдер задаёт IPv6 gateway вне назначенной /64, нужен явный маршрут
`to: ::/0`, `via: <gateway>`, `on-link: true` в netplan. cloud-init при
перезагрузке может перезаписать конфигурацию; чтобы сохранить проверенный netplan,
создайте `/etc/cloud/cloud.cfg.d/99-flr-network.cfg` с
`network: {config: disabled}`. Тогда при смене IP netplan обновляется вручную.

## Перезапуск и восстановление

```sh
sudo systemctl restart awg-quick@awg0
sudo systemctl restart hysteria
```

Перезапуск прерывает соединения затронутого транспорта. Не перезапускайте всё
сразу без необходимости. Каталог ACME-кэша сохраняйте при restart/update.

После восстановления сервера роутер требует 60 s успешных TCP/UDP-проверок канала
перед возвратом VPN в работу; частота проверок 5 s. При перезагрузке единственного
VPS все транспорты временно недоступны, VPN-трафик закрыт, direct работает.

Если ключевой SSH недоступен, используйте консоль/rescue провайдера и его процедуру
сброса root password; в консоли проверьте sshd config и nft rules и возвращайте
ключевой вход, а не постоянный root/password SSH.

Для смены IP сначала проверьте новый endpoint с чистого WAN роутера, обновите
netplan на VPS при необходимости, DNS A-запись и endpoint всех client profiles.
Блокировка IP затрагивает все транспорты на нём; протокольный failover этого не
устраняет — для этого нужен второй сервер.
