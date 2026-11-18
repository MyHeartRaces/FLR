# Сборка и установка образа

Образ GL-MT6000 (OpenWrt 25.12) собирается в GitHub Actions из закреплённых
версий; Mac или другой рабочей станции для сборки не требуется.

## Получить сборку

1. Открыть вкладку **Actions** репозитория [MyHeartRaces/FLR](https://github.com/MyHeartRaces/FLR/actions) и выбрать workflow **Flint 2 runtime image** (`.github/workflows/build.yml`).
2. Запустить **Run workflow** вручную на нужной ветке либо сделать commit в `main` с префиксом `build: final image`.
3. Дождаться успешного job `image` и скачать артефакт запуска.
4. Распаковать ZIP в отдельный каталог. Это артефакт Actions, а не GitHub Release; срок хранения ограничен, локальную копию можно сохранить дольше.
5. Сверить `verification.json`, `build-info.json`, `versions.lock.json` и `image.manifest`. Статус `static-image-checks-passed` означает проверки состава образа, а не испытания устройства.

Проверить целостность скачивания:

```sh
sha256sum -c SHA256SUMS      # на macOS: shasum -a 256 -c SHA256SUMS
```

Все строки должны закончиться `OK`; при несовпадении скачайте и распакуйте заново.

| Файл | Что проверять |
|---|---|
| `*-glinet_gl-mt6000-squashfs-sysupgrade.bin` | Образ только для GL-MT6000; это sysupgrade, не Web Recovery/factory image |
| `build-info.json` | `git_commit` совпадает с коммитом выбранного запуска |
| `versions.lock.json` | Версии OpenWrt, ядра и sing-box; контейнеры и исходники закреплены по digest/commit |
| `image.manifest` | Реальные версии всех установленных пакетов, включая kernel ABI и AWG |
| `verification.json` | Статические проверки образа; `router_contacted` и `recovery_tested` = `false` |
| `packages/` | Собранные APK; ставить их на произвольное ядро OpenWrt нельзя |
| `SHA256SUMS` | Контрольные суммы всей выдачи |

В образ входят AWG (модуль ядра, tools, netifd, LuCI), sing-box (закреплённая
патченая сборка с random-SNI), контроллер и LuCI-меню «Proxy». Политика в образе
нейтральная: локальные адреса остаются локальными, всё остальное идёт через VPN.
Свои списки маршрутизации владелец ставит как приватный overlay (см.
[policy/README.md](../policy/README.md)); персональных ключей и профилей в образе нет.

## Повторить сборку

Повторный запуск использует закреплённые версии; выход нового OpenWrt или
sing-box сам по себе их не обновляет. Обновление pins идёт через workflow
**OpenWrt release pins**, а обновление движков — через compat-lock
([ENGINE-UPDATES.md](ENGINE-UPDATES.md)). Если меняется kernel ABI, AWG
пересобирается тем же SDK. Ошибки зависимостей APK, подписи, устройства и kernel
ABI исправляются в источнике сборки и не обходятся `--force`.

Локальные проверки без установки зависимостей:

```sh
python3 -m unittest discover -s tests -v
```

Go-тесты контроллера используют Linux-only константы сокетов; их запускает
workflow **Flint runtime** (`.github/workflows/runtime.yml`) или Linux-хост.

## Подготовка перед прошивкой

Роутер в ежедневном использовании: не прошивайте и не меняйте его без явного
решения владельца. Перед прошивкой проверьте board identity, текущую разметку и
прошивку, сохраните полный `/etc`, sysupgrade backup, загрузочные разделы
(bootloader, environment, factory, FIP, GPT) и старые kernel/rootfs. Образ
проверяется `/usr/libexec/validate_firmware_image` и `sysupgrade -T`. Загрузчик,
его environment и calibration-разделы не перезаписываются.

Для проверки штатного Web Recovery GL.iNet описывает такой порядок:

1. Заранее скачать официальную прошивку именно GL-MT6000 с [портала GL.iNet](https://dl.gl-inet.com/) и хранить отдельно от sysupgrade.
2. При выключенном питании оставить только компьютер на LAN 2, LAN 3 или LAN 4; LAN 1 не использовать.
3. Удерживая Reset, включить питание; отпустить после смены рисунка LED.
4. На компьютере временно задать `192.168.1.2/24` и открыть `http://192.168.1.1`. Для проверки доступности страницы нажимать Update firmware не нужно.
5. После проверки вернуть сетевые настройки компьютера. Реальное восстановление стирает настройки.

Источник: [официальная инструкция GL.iNet](https://docs.gl-inet.com/router/en/4/faq/debrick/). Доступность Recovery на конкретном устройстве нужно проверять самостоятельно.

Настройка сервера: [SERVER.ru.md](SERVER.ru.md). Установка и управление runtime: [RUNTIME.ru.md](RUNTIME.ru.md).
