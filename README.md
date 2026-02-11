# LearnMap

LearnMap — öğretici amaçlı bir `nmap` yardımcı aracıdır. Menülü bir CLI sunar, kullanıcıya nmap komutlarını öğretir, örnekleri gösterir ve onayla gerçek tarama çalıştırır; sistemde `nmap` yoksa Python tabanlı bir fallback taraması (TCP connect, UDP approx, ping) sunar.

## Özellikler

- Menü tabanlı, iç içe (kategori → seçenek) arayüz.
- Tüm yaygın `nmap` tarama tipleri ve önemli flag'ler listelenir.
- Seçilen işlemin `nmap` karşılığı gösterilir (örnek komut).
- Kullanıcı onayıyla `nmap` çalıştırma; çıktı canlı gösterilir ve dosyaya kaydedilebilir.
- Eğer `nmap` yüklü değilse Python fallback (TCP connect, UDP, ping) ile tarama yapılır.
- Güvenlik/etik uyarısı ve çalıştırma için açık onay (`RUN`) gerektirir.

## Gereksinimler

- Python 3.8+
- (Opsiyonel) `nmap` yüklü ise tam özellik çalışır. Windows için [Nmap indir](https://nmap.org/download.html).

## Hızlı Başlangıç

1. Depoyu klonla veya bu dizine dosyaları koy:

```bash
python learnmap.py
```

2. Menüde seçim yapın: örn `6` → Tarama Türleri → `1` (SYN Stealth) → hedef girin → çalıştırma onayı. Eğer sisteminizde `nmap` yoksa program fallback teklif eder.

## Örnek Kullanım

- `nmap` mevcutsa program şu gibi bir komut gösterir:

```
nmap -sS -p 22,80 192.168.1.5
```

- Çalıştırmak isterseniz `RUN` yazıp onaylayın; sonra çıktı canlı gelir. Dosyaya kaydetmek isterseniz `-oN/-oX/-oG/-oA` formatlarından birini seçebilirsiniz.

- `nmap` yoksa program şöyle bir fallback çalıştırır (örnek):

```
TCP Connect taraması hedef: 192.168.1.5
[OPEN] 22/tcp
  Banner: SSH-2.0-OpenSSH_7.9p1 Debian-10
[CLOSED/FILTERED] 80/tcp
```

## Ekran Görüntüleri

Menü ve tarama çıktısı örnekleri:

![Menü örneği](<img width="890" height="825" alt="Ekran görüntüsü 2026-02-12 013018" src="https://github.com/user-attachments/assets/1f23ac55-a757-4e3c-991f-b0658dd54262" />
)

## Güvenlik ve Etik

Sadece izniniz olan hedeflerde tarama yapın. LearnMap, çalıştırmadan önce açık onay ister ve kullanıcıya yasal uyarı gösterir.

## Katkı

- Hatalar veya iyileştirme önerileri için pull request veya issue açın.

## Lisans

MIT
