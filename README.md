# iplist-go-sidecar

[![Refresh configs](https://github.com/dexogen/iplist-go-sidecar/actions/workflows/refresh-configs.yml/badge.svg?branch=main)](https://github.com/dexogen/iplist-go-sidecar/actions/workflows/refresh-configs.yml)
![Last run](https://img.shields.io/badge/dynamic/json?label=last%20run&query=%24.workflow_runs%5B0%5D.updated_at&url=https%3A%2F%2Fapi.github.com%2Frepos%2Fdexogen%2Fiplist-go-sidecar%2Factions%2Fworkflows%2Frefresh-configs.yml%2Fruns%3Fbranch%3Dmain%26per_page%3D1)

Sidecar-репозиторий для `iplist-go`.

Он собирает конфиги из трех источников и складывает их в один простой layout:

```text
config/
  master/
  beta/
  russia/
```

Источники:

- `master` - `config/` из [`rekryt/iplist`](https://github.com/rekryt/iplist);
- `beta` - дамп публичного API `https://beta.iplist.opencck.org`;
- `russia` - дамп публичного API `https://russia.iplist.opencck.org`.

GitHub Actions регулярно запускает сборку и коммитит изменения только если конфиги реально поменялись.

Обычный push в репозиторий не запускает refresh. Триггеры только такие: ручной запуск, расписание и изменение самого workflow.
