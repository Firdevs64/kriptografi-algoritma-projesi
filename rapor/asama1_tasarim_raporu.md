# AŞAMA 1 – Algoritma Tasarımı ve Şartname

## 1. Proje Amacı
Bu çalışmanın amacı, temel kriptografik prensipleri (ikame, permütasyon, karıştırma/yayılma) kullanarak basit ama özgün bir şifreleme algoritması tasarlamak, daha sonra kodlayıp doğrulamak ve kriptanalizini yapmaktır.

## 2. Algoritma Tipi
- Tip: Blok Şifre
- Blok Boyutu: 16 byte (128 bit)
- Anahtar Boyutu: 8 byte (64 bit)
- Tur Sayısı: 4 tur + son anahtar ekleme (whitening)

## 3. Kullanılan Kriptografik Prensipler
Bu algoritma en az iki temel prensibi içerecek şekilde tasarlanmıştır ve aşağıdaki üç prensibi birlikte kullanır:

1) XOR (Karıştırma – AddRoundKey)
2) İkame (S-Box ile Substitution)
3) Permütasyon (Bit düzeyinde yeniden düzenleme)

Bu yapı, karıştırma (confusion) ve yayılma (diffusion) etkilerini oluşturmayı hedefler.

## 4. Gerekçe ve Felsefe
- XOR adımı, anahtarın doğrudan duruma (state) etkisini sağlar.
- S-Box ikamesi, doğrusal olmayanlık kazandırır ve karıştırmayı güçlendirir.
- Bit permütasyonu, tek bir bit değişiminin çıktının birçok bitine yayılmasını (çığ etkisi) destekler.
- Tur sayısı düşük tutulmuştur; bu durum analiz aşamasında zayıflıkların tartışılabilmesi için bilinçli bir tercihtir.

## 5. Algoritmanın Adım Adım Tanımı

### 5.1 Şifreleme (Encryption)
Girdi:
- Düz metin blok P (16 byte)
- Anahtar K (8 byte)

Çıkış:
- Şifreli blok C (16 byte)

Her tur için (i = 0..3):
1) state = state XOR RK[i]
2) state = SubBytes(state)  (S-Box ikamesi, nibble bazlı)
3) state = PermuteBits(state) (128-bit permütasyon)

Son adım:
- state = state XOR RK[4]
- C = state

### 5.2 Deşifreleme (Decryption)
Girdi: C, K
Çıkış: P

1) state = C XOR RK[4]
2) i = 3..0 için:
   - state = InversePermuteBits(state)
   - state = InvSubBytes(state)
   - state = state XOR RK[i]
3) P = state

## 6. Anahtar Üretimi ve Tur Anahtarı (Key Schedule)
- Anahtar üretimi: Kullanıcı parolası SHA-256 ile özetlenir ve ilk 8 byte alınarak 64-bit anahtar elde edilir.
- Tur anahtarları: Her tur için anahtar döndürme (rotation) ve sabit (round constant) ile XOR uygulanarak 16 byte’lık tur anahtarı üretilir.
Bu yöntem deterministik ve uygulaması kolaydır.

## 7. Matematiksel Gösterim

P ∈ {0,1}^128
K ∈ {0,1}^64

Tur fonksiyonu:
S_{i+1} = π( σ( S_i ⊕ RK_i ) )

Son çıktı:
C = S_4 ⊕ RK_4

Burada:
- ⊕ : XOR
- σ : S-Box ikamesi (SubBytes)
- π : Bit permütasyonu (PermuteBits)
- RK_i : i. tur anahtarı

## 8. Akış Şeması (Flowchart - Metinsel)

ŞİFRELEME:
Başla
→ P ve K al
→ RK üret
→ state = P
→ (4 tur)
   → XOR (RK[i])
   → S-Box ikame
   → Bit permütasyonu
→ Son XOR (RK[4])
→ C üret
→ Bitir

DEŞİFRELEME:
Başla
→ C ve K al
→ RK üret
→ state = C
→ Son XOR (RK[4])
→ (4 tur ters)
   → Ters permütasyon
   → Ters S-Box
   → XOR (RK[i])
→ P üret
→ Bitir

