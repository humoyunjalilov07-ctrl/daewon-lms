# Daewon litsenziya serveri

Bog'liqliksiz Node (18+) server: kalit + qurilma + LMS akkaunt bog'lash, 1 soatlik imzolangan chipta (JWT, HS256).

## Ishga tushirish

```bash
ADMIN_TOKEN="kamida-16-belgili-maxfiy-parol" PORT=3000 node server.js
```

`data.json` avtomatik yaratiladi (ichida JWT maxfiy kaliti bor — uni git'ga qo'shmang, hech kimga bermang).

## Livops.uz ga joylash

1. Papkani (`server.js`, `package.json`) alohida GitHub repoga qo'ying. Repoda `data` nomli papka bo'lmasin (Livops diskni yopib qo'yadi).
2. livops.uz → yangi loyiha → GitHub repo → Node.js avtomatik aniqlanadi.
3. Variables: faqat `ADMIN_TOKEN` (kamida 16 belgi). `PORT` va `DATA_DIR` ni Livops o'zi beradi.
4. `data.json` Livopsda `/app/data` ga yoziladi va redeploydan keyin saqlanib qoladi.
5. Berilgan HTTPS manzildan `/health` ni tekshiring.

## Kalit yaratish va boshqarish

```bash
# yangi kalit (30 kunlik)
curl -X POST http://localhost:3000/admin/keys -H "x-admin-token: $ADMIN_TOKEN" -H "content-type: application/json" -d '{"label":"Ali","days":30}'

# ro'yxat (qaysi qurilma/IP bog'langanini ko'rasiz)
curl http://localhost:3000/admin/keys -H "x-admin-token: $ADMIN_TOKEN"

# o'chirish / tiklash / bog'lanishni tozalash (yangi telefon uchun)
curl -X POST http://localhost:3000/admin/keys/revoke  -H "x-admin-token: $ADMIN_TOKEN" -H "content-type: application/json" -d '{"key":"DW-XXXX-XXXX-XXXX"}'
curl -X POST http://localhost:3000/admin/keys/restore -H "x-admin-token: $ADMIN_TOKEN" -H "content-type: application/json" -d '{"key":"DW-XXXX-XXXX-XXXX"}'
curl -X POST http://localhost:3000/admin/keys/reset   -H "x-admin-token: $ADMIN_TOKEN" -H "content-type: application/json" -d '{"key":"DW-XXXX-XXXX-XXXX"}'
```

## Muhim

- Serverni HTTPS ortida ishlating (reverse proxy yoki hosting TLS). Aks holda kalit ochiq yuboriladi.
- Skriptdagi `LICENSE_SERVER` va `@connect` ni o'z domeningizga almashtiring.
- Reverse proxy ortida bo'lsa, `x-forwarded-for` IP'ni to'g'ri uzatishini tekshiring.
- `data.json` ni git'ga qo'shmang.
