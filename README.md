# MDB Protocol Decoder v10

🚀 **Profesyonel MDB (Multi-Drop Bus) Protokol Çözücü - Saleae Logic Analyzer**

Cashless Device, Coin Changer ve Bill Validator desteği ile gelişmiş 9-bit → 2 byte dönüşüm sistemi.

## 📸 Ekran Görüntüleri

Çözücünün çalışma anından görüntüler:

- **Gerçek zamanlı MDB protokol analizi** - Detaylı komut ayrıştırma
- **Gelişmiş zaman çizelgesi** - POLL/ACK döngüleri ve VEND işlemleri
- **Konsol çıktısı** - İnsan tarafından okunabilir komut açıklamaları
- **Profesyonel görselleştirme** - Otomat iletişim protokolleri

## 🎯 Amaç

Bu çözücü şunlar için tasarlanmıştır:

- **MDB Komut Detaylandırma**: Tüm MDB protokol komutlarını ayrıştırma ve tanımlama
- **Veri Çıkarma**: MDB paketlerinden veri çıkarma ve yorumlama
- **Gelişmiş Analiz**: Otomat iletişimlerinin insan tarafından okunabilir analizi
- **Gerçek Zamanlı Çözümleme**: Protokol hata ayıklama sırasında canlı analiz

## ⚡ Temel Özellikler

### 🔧 Teknik Yetenekler

- **9-bit → 2 byte dönüşüm**: MDB'nin benzersiz veri formatının doğru işlenmesi
- **Paket uzunluğu analizi**: Paket boyutuna göre dinamik ayrıştırma
- **Komut-Cevap korelasyonu**: Doğru cevap yorumlama için komut bağlamı takibi
- **Modüler dispatch mimarisi**: Her periferik tipi için ayrı handler metodları
- **Gelişmiş frame tipleri**: Kritik işlemler için özel analiz

### 📊 Desteklenen MDB Komutları

#### Cashless Device (0x10–0x17)

| Komut     | Kod  | Açıklama                 |
| --------- | ---- | ------------------------ |
| RESET     | 0x10 | Sistem sıfırlama komutu  |
| SETUP     | 0x11 | Cihaz yapılandırma       |
| POLL      | 0x12 | Durum sorgulama          |
| VEND      | 0x13 | Satış işlemleri          |
| READER    | 0x14 | Kart okuyucu komutları   |
| REVALUE   | 0x15 | Kredi işlemleri          |
| EXPANSION | 0x17 | Genişletilmiş özellikler |

#### Coin Changer (0x08–0x0F)

| Komut            | Kod  | Açıklama                                   |
| ---------------- | ---- | ------------------------------------------ |
| COIN_RESET       | 0x08 | Bozuk para makinesi sıfırlama              |
| COIN_SETUP       | 0x09 | Cihaz yapılandırma bilgileri               |
| COIN_TUBE_STATUS | 0x0A | Tüp doluluk durumu                         |
| COIN_POLL        | 0x0B | Etkinlik durumu sorgulama                  |
| COIN_TYPE        | 0x0C | Para tipi etkinleştirme/devre dışı bırakma |
| COIN_DISPENSE    | 0x0D | Para verme komutu                          |
| COIN_EXPANSION   | 0x0F | Genişletilmiş özellikler                   |

#### Bill Validator (0x30–0x37)

| Komut          | Kod  | Açıklama                                      |
| -------------- | ---- | --------------------------------------------- |
| BILL_RESET     | 0x30 | Banknot doğrulayıcı sıfırlama                 |
| BILL_SETUP     | 0x31 | Yapılandırma durum bilgisi                    |
| BILL_SECURITY  | 0x32 | Güvenlik modu ayarı                           |
| BILL_POLL      | 0x33 | Etkinlik durumu sorgulama                     |
| BILL_TYPE      | 0x34 | Banknot tipi etkinleştirme/devre dışı bırakma |
| BILL_ESCROW    | 0x35 | Emanet işlemi (yığınla veya iade et)          |
| BILL_STACKER   | 0x36 | Yığın doluluk durumu                          |
| BILL_EXPANSION | 0x37 | Genişletilmiş özellikler                      |

### 🎨 Gelişmiş Analiz

- **BEGIN_SESSION**: Detaylı bakiye ve seviye analizi
- **PERIPHERAL_ID**: Üretici ve seri numarası çıkarma
- **VEND_APPROVED/DENIED**: İşlem tutarı ayrıştırma
- **READER_CONFIG**: Özellik seviyesi ve ülke kodu analizi
- **SELECTION_REQUEST**: Ürün seçimi ve bakiye bilgisi
- **DISPLAY_REQUEST**: Gösterim süresi ve veri ayrıştırma
- **MALFUNCTION**: Hata kodu tanımlama
- **COIN_DEPOSITED/DISPENSED**: Para tipi ve rota bilgisi
- **BILL_ACCEPTED/ESCROW/REJECTED**: Banknot durumu ve yönlendirme

## 📖 Sembol Rehberi

Çözücüyü çalıştırdığınızda debug çıktısında bu sembolleri göreceksiniz:

| Sembol | Anlam       | Açıklama                    |
| ------ | ----------- | --------------------------- |
| `->`   | ACK Cevabı  | Cihaz VMC komutunu onaylar  |
| `<-`   | POLL Komutu | VMC cihazdan durum sorgular |

## 🚀 Kurulum

1. Bu depoyu **indirin** veya klonlayın
2. Klasörü Saleae Logic 2 eklenti dizinine **kopyalayın**:
   - **Windows**: `%USERPROFILE%\Documents\Saleae\Logic2\Marketplace\Extensions`
   - **macOS**: `~/Documents/Saleae/Logic2/Marketplace/Extensions`
   - **Linux**: `~/Documents/Saleae/Logic2/Marketplace/Extensions`
3. Saleae Logic 2'yi **yeniden başlatın**
4. **Analyzer Ekle** → "MDB Protocol Decoder" arayın

## 🔌 Kullanım

### Temel Kurulum

1. Lojik analizörünüzü MDB veri yoluna bağlayın
2. Örnekleme hızını **1 MHz veya üzeri** ayarlayın
3. Veri kanalınıza MDB Protocol Decoder'ı ekleyin
4. Analizör ayarlarını yapılandırın:
   - **Veri Kanalı**: MDB veri hattınızı seçin
   - **Saat Kanalı**: MDB saat hattınızı seçin (varsa)

### Sonuçları Okuma

#### 📱 Zaman Çizelgesi Görünümü

- **POLL**: Basit sorgulama komutları
- **ACK**: Onay cevapları
- **CMD: 0x113 (VEND)**: Detaylı komut bilgisi
- **DATA: 0x001**: Ham veri paketleri
- **BEGIN SESSION - Tutar: 500, Seviye: 1**: Gelişmiş analiz
- **COIN DEPOSITED - Tip: 3, Rota: Tüp**: Bozuk para olayı
- **BILL ACCEPTED - Tip: 2, Rota: BILL_STACKED**: Banknot olayı

#### 🖥️ Konsol Çıktısı

Detaylı hata ayıklama bilgisi:

```
VEND_REQUEST bytes: 011300370064 (uzunluk: 6)
  Fiyat: 100, Ürün No: 55
VEND->VEND_APPROVED cevap: 000500640000 (uzunluk: 6)
  Satış Tutarı: 100
```

## 📋 Örnek Çıktılar

### Tipik MDB İşlemi (Cashless)

```
<- POLL                          # VMC cihazı sorgular
-> ACK                           # Cihaz cevap verir
CMD: 0x113 (VEND)                # VMC satış komutu gönderir
VEND APPROVED - Tutar: 150       # Cihaz 150 birim onaylar
BEGIN SESSION - Tutar: 500, Seviye: 1  # Oturum başlar
```

### Coin Changer İşlemi

```
<- COIN_POLL                     # VMC para makinesini sorgular
COIN DEPOSITED - Tip: 3, Rota: Tüp  # Bozuk para tüpe yönlendirildi
COIN TUBES - Dolu: T0:5, T1:3, T2:8  # Tüp durumu
```

### Bill Validator İşlemi

```
<- BILL_POLL                     # VMC banknot doğrulayıcıyı sorgular
BILL ESCROW - Tip: 2            # Banknot emanette
BILL ACCEPTED - Tip: 2, Rota: BILL_STACKED  # Banknot yığına eklendi
BILL STACKER - Dolu: HAYIR, Adet: 45  # Yığın durumu
```

### Kart Okuyucu İşlemi

```
CMD: 0x114 (READER)
READER CONFIG - Seviye: 2, Ülke: 0x0840
PERIPHERAL ID - Üretici: ABC, SN: 12345678
```

## 🔧 Gelişmiş Özellikler

### Protokol Doğrulama

- **Checksum doğrulama**: Otomatik MDB checksum kontrolü
- **Sıra takibi**: Komut-cevap çiftlerini izler
- **Hata tespiti**: Protokol ihlallerini tanımlar

### Veri Analizi

- **Para birimi işleme**: Para değerlerinin otomatik dönüşümü
- **Oturum takibi**: Tam işlem akışlarını izler
- **Cihaz tanımlama**: Üretici ve model bilgisi çıkarma

## 🛠️ Geliştirme

### Kod Yapısı (v10 - Modüler Mimari)

```python
class Hla(HighLevelAnalyzer):
    # Sabitler
    KOMUT_ISIMLERI = {0x08: "COIN_RESET", 0x10: "RESET", 0x30: "BILL_RESET", ...}
    POLL_CEVAP_ISIMLERI = {0x01: "READER_CONFIG", 0x03: "BEGIN_SESSION", ...}

    def __init__(self):       # Başlatma
    def decode(self, frame):  # Ana dispatcher

    # Alt işleyiciler
    def _komut_isle(...)           # Komut ayrımı
    def _veri_isle(...)            # Veri ayrımı
    def _uzun_paket_analiz(...)    # Çoklu byte analiz
    def _poll_cevap(...)           # POLL cevapları
    def _vend_cevap(...)           # VEND cevapları
    def _coin_poll_cevap(...)      # Coin olayları
    def _bill_poll_cevap(...)      # Bill olayları
    # ... ve dahası
```

### Temel Bileşenler

- **9-bit Dönüşüm**: 2 byte'ı 9-bit MDB değerine dönüştürme
- **Komut Takibi**: `BironcekiKomut` ile durum yönetimi
- **Dispatch Tablosu**: Dictionary tabanlı cevap yönlendirme
- **Modüler İşleyiciler**: Her periferik tipi için ayrı metodlar

## 📚 MDB Protokol Referansı

### Paket Yapısı

```
[Veri Byte][Kontrol Byte]
    |           |
    |           └── Bit 0: Komut/Veri bayrağı
    |               Bit 1-7: Ayrılmış
    └── 8-bit yük verisi
```

### 9-bit Değer Formatı

```
Bit 8: Komut bayrağı (1=Komut, 0=Veri)
Bit 7-0: Gerçek veri/komut kodu
```

### Periferik Adres Aralıkları

```
0x08-0x0F: Coin Changer (Bozuk Para Makinesi)
0x10-0x17: Cashless Device (Nakit Dışı Cihaz)
0x30-0x37: Bill Validator (Banknot Doğrulayıcı)
```

![image](https://github.com/user-attachments/assets/22a23bdf-b255-4400-b75b-2aa334202353)
![image](https://github.com/user-attachments/assets/b07159b1-9819-449b-b632-81263b228653)
![image](https://github.com/user-attachments/assets/1a724ec8-8745-4392-93c1-129e8f91c481)

## 🤝 Katkıda Bulunma

Katkılarınızı bekliyoruz! İşte yardımcı olabileceğiniz yollar:

1. **🐛 Hata Raporları**: Sorun mu buldunuz? Detaylı bir issue açın
2. **💡 Özellik İstekleri**: Fikirlerinizi paylaşın!
3. **🔧 Kod Katkıları**: Fork yapın, geliştirin ve PR gönderin
4. **📖 Dokümantasyon**: Bu README'yi geliştirmeye yardım edin

## 📄 Lisans

Bu proje açık kaynaklıdır. Kullanmakta, değiştirmekte ve dağıtmakta özgürsünüz.

## 👨‍💻 Yazar

**ByTaymur**

- GitHub: [@ByTaymur](https://github.com/ByTaymur)
- Uzmanlık: Gömülü sistemler, protokol analizi, otomat teknolojisi

## 🙏 Teşekkürler

- **Saleae Ekibi**: Mükemmel Logic Analyzer platformu için
- **MDB Topluluğu**: Protokol dokümantasyonu ve destek için
- **Otomat Endüstrisi**: Gerçek dünya test senaryoları için

## 📞 Destek

Sorun mu yaşıyorsunuz? İşte yardım almanın yolları:

1. **📖 Dokümantasyonu Kontrol Edin**: Bu README'yi dikkatlice inceleyin
2. **🔍 Mevcut Issue'ları Arayın**: Mevcut çözümleri arayın
3. **💬 Issue Açın**: Detaylı hata raporu oluşturun
4. **📧 İletişim**: GitHub üzerinden ulaşın

---

⭐ **Bu proje işinize yaradıysa yıldız verin!** ⭐

_Gömülü sistemler topluluğu için ❤️ ile yapıldı_
