# ISA-PROJECT

### Tunelování datových přenosů přes DNS dotazy

### Date: 2022-10-20

### Autor: Zdeněk Lapeš <lapes.zdenek@gmail.com> (xlapes02)

## Popis programu

Program `dns_sender` zakodováná data ze souboru/STDIN přes UDP datragramy
druhému programu `dns_receiver` který data přijímá portu UDP a pro
danou basehost url adresu.

## Kompilace a spuštění programů

Kompilaci zajišťuje program `make`, který je možné spustit následovně:

```shell
make          # Přeloží dns_sender i dns_receiver
make sender   # Přeloží dns_sender
make receiver # Přeloží dns_receiver
make pack     # Zabali projekt
```

### Spouštění programu sender:

```shell
# Format: dns_sender [-u UPSTREAM_DNS_IP] {BASE_HOST} {DST_FILEPATH} [SRC_FILEPATH]

dns_sender -u 127.0.0.1 example.com data.txt ./data.txt
echo "abc" | dns_sender -u 127.0.0.1 example.com data.txt
```

### Spouštění programu receiver:

```shell
# Format: dns_receiver {BASE_HOST} {DST_FILEPATH}

dns_receiver example.com ./data
```

## Soubory:

```text
├── Makefile
├── README.md
├── dokumentace.pdf
├── common
│    ├── argument_parser.c
│    ├── argument_parser.h
│    ├── base32.c
│    ├── base32.h
│    ├── dns_helper.c
│    ├── dns_helper.h
│    ├── initializations.c
│    └── initializations.h
├── receiver
│    ├── dns_receiver.c
│    ├── dns_receiver_events.c
│    ├── dns_receiver_events.h
│    ├── receiver_implementation.c
│    └── receiver_implementation.h
├── middleman
│    ├── middleman.c
│    └── middleman.h
└── sender
    ├── dns_sender.c
    ├── dns_sender_events.c
    ├── dns_sender_events.h
    ├── sender_implementation.c
    └── sender_implementation.h
```
