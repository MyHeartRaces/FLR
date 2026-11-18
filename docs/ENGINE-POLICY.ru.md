> **Update 2026-11-18 (English note).** The sing-box pin is now 1.14.4
> (upstream commit `c005f353…`) with the random-SNI patch from
> `client/sing-box-random-sni`, binary version `1.14.4-flr-random-sni.1`,
> apk version `1.14.4.1` (`build/versions.lock.json`). The 1.14.2 text below
> is historical. Updates between images: `docs/ENGINE-UPDATES.md`.

# Выбор движков для нового образа

Sing-box собирается из закреплённых исходников 1.14.2, commit
`af6e64c3b69e6132ebaee0e1a3d24e93903f6709`, Go 1.26.8, CGO=0,
tags `with_quic,with_wireguard,with_utls,with_gvisor`. Receipt содержит SHA исходников,
go.mod/go.sum, обеих статических целей ARM64/AMD64 и фактически связанных
модулей. Официальный prebuilt не заменяет эту сборку при ошибке или обновлении
resolver. Смена закреплённого исходника требует нового проверенного pin.

Для Xray, wstunnel, zapret2 и AWG при каждой CI-сборке выбираются последние
совместимые стабильные официальные выпуски и исходники module/tools. Числа
в `build/versions.lock.json` служат записью предыдущего состава для повторно
проверяемого fallback; это не верхняя граница версий. Рецепты пакетов получают
выбранные версии, commit и SHA256 из созданного для этой сборки lock-файла.
Платформа OpenWrt, SDK/ImageBuilder, kernel ABI, feeds, Go и Actions сохраняют
свои точные pins.

Выбор ограничен восемью новейшими стабильными кандидатами и исходной записью
fallback. История запрашивается страницами по два выпуска, не более 16 страниц;
предел JSON-ответа остаётся 8 MiB. Для AWG-модуля используются числовые официальные tags: этот проект
не публикует GitHub Releases. Nightly, draft и prerelease не выбираются.
Несовместимость фиксируется с причиной; следующий кандидат проходит те же
проверки. Ошибки API, сети, digest или среды исполнения останавливают сборку.
Если SDK не собрал предварительно выбранную пару AWG, сборка завершается
ошибкой; такой сбой не объявляется несовместимостью без установленной причины
и не вызывает скрытого fallback.

В существующем Linux CI production importer/renderers создают синтетические
конфиги HY2 Gecko/Salamander, TLS/Reality и транспортов, XHTTP modes, SS2022 с
ShadowTLS и WGWS wrapper/compact URI. Точные конфиги проверяют
matching-version AMD64 движки: `sing-box check`, `xray run -test`, парсер owned
wstunnel CLI и `nfqws2 --dry-run` с фиксированными Lua/параметрами. Xray дополнительно
проверяется по полям matching-version официальной transport schema, поскольку
его JSON loader способен игнорировать неизвестные поля. AWG проходит проверку
официальных Git blobs, полного набора требуемых 3.1 UAPI индексов и их совпадения
между module/tools; разрешение на выпуск даёт только последующая успешная
SDK-сборка и проверка module ABI/netifd в rootfs.

Нативный Xray REALITY допускает только RAW/tcp, XHTTP/splithttp и gRPC.
REALITY+WS и другие неподдерживаемые сочетания явно отклоняются при импорте;
TLS+WS остаётся поддерживаемым, включая early data. Это ограничение не
переносится на отдельный backend sing-box без доказательства.

Xray WS `maxEarlyData` переводится в нативный `ed` query пути. Допустимы
отсутствующий `earlyDataHeaderName` или стандартный `Sec-WebSocket-Protocol`
без учёта регистра; другие заголовки явно отклоняются при импорте, поскольку
нативный Xray их не реализует. Custom early-data headers sing-box сохраняются.
Значение должно быть целым 0…2147483647; ноль не добавляет новый query.
Дублирующийся, неверный или конфликтующий `ed`, изменение прочих path/query
байтов при нативной нормализации и конфликт со статическим
`Sec-WebSocket-Protocol` отклоняются. Схема всех семи gRPC полей и matching-source
WS Build/dialer проверяются вместе с nondefault production-rendered fixtures.

Fallback разрешён только при установленном отсутствии поддерживаемой схемы,
ABI/CLI возможности или распознанном отказе парсера. Сигнал, crash, timeout и
неизвестный nonzero native status завершают сборку ошибкой. Для Xray/nfqws2
неизвестные сообщения об ошибке не угадываются как несовместимость.

Отдельные официальные ARM64 archives и SHA256 определяют байты пакетов.
SDK и inspector сравнивают ARM64 бинарники, Lua и лицензии с payloads,
проверенными resolver; AMD64 программы в образ не включаются. Выдача содержит
resolved `versions.lock.json`, исходный `source-versions.lock.json`, SDK feed
provenance, SDK report, build-info и итоговые SHA256SUMS. При сбоях CI сохраняет
ограниченный вывод и полный SDK/ImageBuilder log без приватного signing payload.

Это проверка схемы, парсера и состава образа, а не проверка работы соединений
с сервером. Она не доказывает boot, recovery, реальное прохождение трафика,
работу всех комбинаций пользовательских параметров или результат обхода ISP.
Флаги hardware/end-to-end/ISP остаются false; VPN и direct bypass выключены
по умолчанию. Постоянный direct SOCKS 1080 и временный 1088 остаются отдельными
контрактами контроллера и проверяются его существующей Go suite.
