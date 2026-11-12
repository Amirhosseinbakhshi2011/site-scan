# Aegis Sentinel AI

**سیستم ارزیابی امنیتی و پایش آسیب‌پذیری وب‌سایت (Remote Website Security Assessment)**

نسخه ۱.۰ — پایتون / FastAPI

---

## هدف پروژه

Aegis Sentinel AI یک سیستم **غیرتخریبی** و **مجاز** برای ارزیابی امنیت وب‌سایت‌ها از طریق دامنه عمومی و رابط‌های HTTP/HTTPS است. این ابزار **به کد منبع وب‌سایت دسترسی ندارد** و فقط روی دامنه‌هایی که مالکیت آن‌ها تأیید شده باشد اسکن انجام می‌دهد.

### اصول ایمنی اسکنر

- فقط درخواست‌های HTTP امن و محدود
- بدون payload مخرب، بدون brute-force، بدون DoS
- بدون تغییر داده روی سایت هدف
- بدون دور زدن احراز هویت
- محدودیت نرخ درخواست و اندازه پاسخ
- تأیید مالکیت دامنه قبل از هر اسکن

---

## قابلیت‌ها

| دسته | بررسی‌ها |
|------|----------|
| SSL/TLS | اعتبار گواهی، انقضا، HTTPS، ریدایرکت HTTP→HTTPS، نسخه TLS |
| هدرهای امنیتی | CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy |
| کوکی‌ها | Secure, HttpOnly, SameSite |
| افشای عمومی | صفحات ادمین رایج، directory listing، فایل‌های پشتیبان/کانفیگ متداول |
| DNS | SPF, DMARC, رکوردهای A/MX |
| اپلیکیشن وب | CORS ناامن، شاخص open redirect، افشای اطلاعات در پاسخ |

---

## پیش‌نیازها

- Python 3.12+
- (اختیاری) Docker و Docker Compose برای استقرار تولید
- دسترسی شبکه خروجی برای اسکن دامنه‌های مجاز

---

## نصب سریع (بدون Docker)

```bash
# کلون یا استخراج پروژه
cd Aegis-Sentinel-AI

# محیط مجازی
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activater

# وابستگی‌ها
pip install -r requirements.txt

# پیکربندی
cp .env.example .env
# SECRET_KEY را حتماً تغییر دهید (حداقل ۳۲ کاراکتر)

# اجرا
mkdir -p data
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

سپس مرورگر را باز کنید: [http://127.0.0.1:8000](http://127.0.0.1:8000)

- API Docs: [http://127.0.0.1:8000/api/docs](http://127.0.0.1:8000/api/docs)
- کاربر پیش‌فرض: مقدار `FIRST_SUPERUSER_EMAIL` و `FIRST_SUPERUSER_PASSWORD` در `.env`

---

## استقرار با Docker

```bash
export SECRET_KEY="یک-کلید-بلند-و-تصادفی-حداقل-۳۲-کاراکتر"
docker compose up -d --build
```

سرویس روی پورت ۸۰۰۰ در دسترس است. پایگاه داده PostgreSQL و Redis نیز بالا می‌آیند.

---

## جریان کار پیشنهادی

1. ورود به داشبورد با کاربر مدیر
2. افزودن دامنه (فقط hostname مثل `example.com`)
3. تنظیم توکن تأیید:
   - رکورد DNS TXT با مقدار توکن نمایش‌داده‌شده، **یا**
   - فایل `/.well-known/aegis-sentinel-verification.txt` حاوی همان توکن
4. کلیک روی «تأیید مالکیت»
5. پس از تأیید، «شروع اسکن»
6. مشاهده امتیاز، یافته‌ها و راهکارهای پیشنهادی

---

## ساختار پروژه

```
Aegis-Sentinel-AI/
├── app/
│   ├── api/           # روترهای FastAPI
│   ├── core/          # تنظیمات، امنیت، لاگ
│   ├── db/            # SQLAlchemy
│   ├── models/        # مدل‌های داده
│   ├── schemas/       # Pydantic
│   ├── services/
│   │   ├── checks/    # ماژول‌های بررسی امنیتی
│   │   ├── scanner/   # موتور اسکن و کلاینت HTTP امن
│   │   ├── reporting/
│   │   └── domain_verification.py
│   └── main.py
├── dashboard/         # قالب HTML/JS داشبورد RTL فارسی
├── tests/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env.example
└── README.md
```

---

## محدودیت‌ها و هشدارها

- این ابزار جایگزین تست نفوذ حرفه‌ای کامل نیست.
- یافته‌ها ممکن است مثبت کاذب داشته باشند؛ همیشه بررسی دستی کنید.
- فقط دامنه‌هایی را اسکن کنید که مالک آن‌ها هستید یا مجوز کتبی دارید.
- در محیط این سندباکس، سرویس‌های خارجی (PostgreSQL واقعی، Celery worker جدا، اعلان تلگرام) به‌طور کامل تست نشده‌اند؛ برای تولید از Docker Compose استفاده کنید.
- اسکن‌ها به‌صورت همزمان در همان فرآیند اجرا می‌شوند؛ برای صف واقعی Celery + Redis را فعال کنید.

---

## تولید گزارش

از API می‌توانید جزئیات اسکن را به صورت JSON دریافت کنید. ماژول `app/services/reporting/report.py` قابلیت تولید PDF ساده نیز دارد.

نمونه گزارش JSON در پوشه `docs/sample_report.json` قرار دارد.

---

## توسعه و تست

```bash
pytest tests/ -v
```

---

## مجوز و مسئولیت

استفاده از این نرم‌افزار صرفاً برای ارزیابی امنیتی **مجاز** است. توسعه‌دهنده مسئولیتی در قبال استفاده غیرقانونی یا خسارات ناشی از پیکربندی نادرست ندارد.

---

ساخته‌شده با تمرکز بر قابلیت اطمینان، ایمنی اسکنر و معماری تمیز.
