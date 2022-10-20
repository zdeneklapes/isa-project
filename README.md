# ISA-PROJECT

### Tunelování datových přenosů přes DNS dotazy

### Date: 2022-10-20

### Autor: Zdeněk Lapeš <lapes.zdenek@gmail.com> (xlapes02)

## Popis programu

Program `dns_sender` posílá po zakodování náčtená data ze souboru/ze STDIN přes UDP datragramy
druhému programu `dns_receiver` který je připraven data přijímat na na daném UDP qname,
které má format *.{BASE_HOST} např. ABCDE.example.com.

## Kompilace a spuštění programů

Kompilaci zajišťuje program `make`, který je možné spustit následovně:

```shell
make          # Přeloží dns_sender i dns_receiver
make all      # Přeloží dns_sender i dns_receiver
make sender   # Přeloží dns_sender
make receiver # Přeloží dns_receiver
```

### Spouštění programu sender:

```shell
dns_sender -u 127.0.0.1 example.com data.txt ./data.txt
echo "abc" | dns_sender -u 127.0.0.1 example.com data.txt
```

### Spouštění programu receiver:

```shell
dns_receiver {BASE_HOST} {DST_FILEPATH}
dns_receiver example.com ./data
```

## Soubory:

```text
├── Makefile
├── README.md
├── manual.pdf
├── common
│   ├── base32.c
│   ├── base32.h
│   ├── dns_helper.c
│   └── dns_helper.h
├── receiver
│   ├── dns_receiver.c
│   ├── dns_receiver_events.c
│   └── dns_receiver_events.h
└── sender
    ├── dns_sender.c
    ├── dns_sender_events.c
    └── dns_sender_events.h
```
