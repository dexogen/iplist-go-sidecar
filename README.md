# iplist-go-sidecar

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
