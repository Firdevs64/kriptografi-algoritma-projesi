# AŞAMA 3 – Kriptanaliz ve Analiz Raporu

## 1. Hedef Algoritma
- Algoritma: Blok şifre (128-bit blok, 64-bit anahtar)
- Temel adımlar: XOR + S-Box ikamesi + Bit permütasyonu
- Tur sayısı: 4 tur + son anahtar ekleme

## 2. Seçilen Saldırı Türü
Bu çalışmada aşağıdaki analizler uygulanmıştır:
1) Bilinen düz metin temelli değerlendirme (Known-Plaintext mantığı ile gözlem)
2) Anahtar hassasiyeti / çığ (avalanche) testi (tek bit anahtar değişimi)
3) Zayıflık tartışması (tur sayısı ve anahtar genişletmenin basitliği üzerinden)

## 3. Saldırı / Analiz Yöntemi (Adım Adım)

### 3.1 Doğrulama (Test 1)
- Seçilen bir düz metin şifrelenmiştir.
- Elde edilen şifreli metin tekrar deşifre edilmiştir.
- Deşifre sonucu orijinal düz metin ile aynı çıkmıştır.
Bu, algoritmanın fonksiyonel olarak doğru çalıştığını gösterir.

### 3.2 Anahtar Hassasiyeti – Çığ Etkisi (Test 2)
- Aynı düz metin için anahtarın sadece 1 biti değiştirilmiştir.
- Yeni anahtar ile tekrar şifreleme yapılmıştır.
- Elde edilen şifreli metin, önceki şifreli metinden büyük ölçüde farklı çıkmıştır.
Bu durum, anahtardaki küçük değişimlerin çıktı üzerinde büyük değişim oluşturduğunu (avalanche etkisi) destekler.

Not: Proje kapsamında bu testler otomatik olarak `pytest` ile çalıştırılmıştır ve tüm testler geçmiştir.

## 4. Sonuçlar ve Zayıflıklar

### 4.1 Güçlü Yönler
- S-Box kullanımı doğrusal olmayanlık kazandırır (confusion).
- Bit permütasyonu yayılmayı artırır (diffusion).
- XOR adımı anahtarın her turda etki etmesini sağlar.

### 4.2 Zayıf Yönler (Kritik)
- Tur sayısının düşük olması (4 tur), güvenlik marjını düşürür.
- Anahtar genişletme (key schedule) basit tutulmuştur; tur anahtarları arasında ilişki oluşabilir.
- Bu sebeplerle algoritma eğitim amaçlıdır; gerçek dünyada kullanılacaksa geliştirilmelidir.

## 5. Öneriler
- Tur sayısı artırılmalı (ör. 10–12+)
- Anahtar genişletme daha karmaşık hale getirilmeli
- Gerçek kullanım senaryosunda uygun çalışma modu (CBC/CTR) ve rastgele IV kullanılmalı

## 6. Genel Değerlendirme
Bu proje kapsamında algoritma tasarlanmış, kodlanmış, test edilerek doğrulanmış ve temel güvenlik analizi yapılmıştır. Sonuç olarak algoritma eğitim amaçlı olarak işlevsel ve anlaşılır bir örnek sunmaktadır.

