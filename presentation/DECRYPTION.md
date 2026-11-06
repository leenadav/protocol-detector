# פענוח TLS ו־App-ID ל־POC

נוסף מסלול ניתוח offline: capture + קובץ SSLKEYLOGFILE → איחוד TCP → פענוח ואימות רשומות TLS → Inspector → App-ID.
הקוד נמצא ב־`poc_decryption/`; הפרונט וכל השרת נכללים בתיקיית `presentation/` בפרויקט המקומי.
עותק המנוע שבתיקייה עודכן ל־v0.65.0 עם SHA המתועד ב־SOURCE.json. תיקיית המקור המקומית הישנה לא שודרגה ולא נדרסה.

## שימוש

1. פתח את הממשק דרך קובץ ההפעלה ובחר **Decryption & App-ID**.
2. להדגמה ללא הכנות, לחץ **Show encrypted application demo**. זהו חיבור OpenSSL אמיתי בזיכרון, ללא תעבורת רשת.
3. לקובץ שלך: העלה PCAP/PCAPNG ואת קובץ מפתחות הדפדפן המתאים ולחץ **Decrypt & identify application**.
4. לחץ על שורת התוצאה לפרטים: TLS חיצוני, פרוטוקול פנימי, אפליקציה, מספר רשומות שאומתו והראיות המצומצמות.

אפשר להפיק מפתחות מדפדפן בדיקה שתומך במשתנה SSLKEYLOGFILE, שמוגדר לפני הפעלת תהליך הדפדפן.
למשל Firefox ב־macOS, לאחר שסגרת אותו, עם נתיב חדש למפתחות:

```sh
SSLKEYLOGFILE="$HOME/Desktop/poc-tls.keys" /Applications/Firefox.app/Contents/MacOS/firefox
```

יש להתחיל את ה־capture לפני פתיחת חיבור הבדיקה, לבחור חיבור TLS מעל TCP ולא QUIC/HTTP3,
ולהשתמש באותו capture ובאותו key log. קובץ ישן בלי מפתחות לא ניתן לפענוח בדיעבד באמצעות הפעלת המשתנה.
הפקודה לעיל היא הוראה ידנית; לא שונו הגדרות הדפדפן במחשב. המפתחות מאפשרים קריאת תעבורת הבדיקה,
ולכן אינם מיועדים להוספה ל־Git. ההרצה הבאה בלי המשתנה אינה מפעילה key logging.

## מה נתמך

- TLS 1.2: ECDHE-RSA-AES128-GCM-SHA256 ו־ECDHE-RSA-AES256-GCM-SHA384, באמצעות CLIENT_RANDOM (master secret באורך 48 בתים).
- TLS 1.3 KeyUpdate: גזירת מפתח ו־IV חדשים ואיפוס מונה הרשומות, עד 32 החלפות לכל כיוון.
- כפתור Show encrypted application demo בעמוד הראשי מייצר שלושה חיבורי OpenSSL בזיכרון, מפענח ומציג WebDAV, web-browsing ו־RESP. RESP הוא פרוטוקול שמשמש Redis, לא הוכחה לזהות מוצר Redis.


- TLS 1.3: AES-128-GCM/SHA256, AES-256-GCM/SHA384, ChaCha20-Poly1305/SHA256.
- מפתחות handshake ומפתחות application של שני הכיוונים, בהתאם ל־ClientHello random.
- מקטעי TCP שלא הגיעו בסדר, כפילויות זהות ופיצול רשומות/הודעות handshake.
- אימות AEAD של כל הרשומות שבטווח הנתמך לפני פרסום זיהוי מתוך plaintext.
- זיהוי אפליקציות מתוך הקטלוג הקיים. למשל PROPFIND בתוך TLS מזוהה כ־WebDAV; HTTP רגיל עשוי להישאר web-browsing.

## גבולות מפורשים

### לכידה ופענוח בהפעלה אחת

בעמוד Overview מאוחדים הלכידה והפענוח. בחר ממשק רשת,
הזן נתיב מוחלט לקובץ SSLKEYLOGFILE קיים של דפדפן הבדיקה והתחל לפני פתיחת חיבור חדש.
אותו עובד Python קורא את הפאקטות, קורא מפתחות חדשים ומעדכן App-ID; tcpdump נשאר תהליך
עזר ללכידת פאקטות בלבד. אין צורך להעלות capture ידנית או לעצור כדי לראות תוצאות.
Start capture מפעיל גם פענוח כאשר מוזן נתיב מפתחות. Stop capture עוצר את שתי הפעולות יחד.
התוצאות מופיעות ב־Live logs, עם פילטר Application; ניתוח קובץ נשאר בלשונית הנפרדת. אין הפעלת דפדפן או פרוקסי אוטומטית.

המסלול החי מוגבל ל־120 שניות ול־2 MiB של capture בזיכרון, 20,000 פריימים ו־64 חיבורים.
קובץ המפתחות מוגבל ל־256 KiB, חייב להיות קובץ רגיל בבעלות המשתמש, ונקרא מאותו file descriptor;
החלפתו בקובץ אחר מחייבת הפעלה מחדש. אין שמירת capture או plaintext בדיסק.
כל שנייה לכל היותר נבדק מחדש snapshot מוגבל, ולא ממומש עדיין פענוח רשומות אינקרמנטלי יעיל.
זהו מסלול הדגמה, לא הבטחת latency: עבודה חוזרת גדלה עם ה־capture. הודעה חלקית או מפתח חסר
עשויים להציג unavailable עד הגעתם; התוצאות זמניות ואובדן capture מדווח מבטל אותן.
ללא counters של tcpdump אין הוכחה שלא אבדו פאקטות.

- אין CBC, TLS 1.0/1.1, QUIC, 0-RTT, HelloRetryRequest, STARTTLS, renegotiation או חיבור שמתחיל באמצע הזרם.
- זה אינו פרוקסי ואינו מייצר תעודות לאתרים. לכידה רגילה נשארת ללא פענוח; המסלול החי החדש דורש key log.
- מגבלות: 8 MiB capture, 20,000 פריימים, 64 חיבורי TCP, 256 KiB לכל כיוון ו־25 שניות לעובד.
- חוסר במקטעים, התנגשות בבתים חופפים, שימוש מחדש באותו tuple או רשומה חסרה גורמים לסירוב לפענח את החיבור.
- אימות תגי AEAD באמצעות מפתחות שסופקו אינו אימות זהות השרת, אמון בתעודה או בדיקת Finished מול transcript.
- אין אימות מלא של פרוטוקול TLS; זהו פרופיל POC מוגבל, שאינו מיועד לנתיב העברת תעבורה בייצור.
- לא מוצגים payload, נתיב URL, hostname או סודות. הפלט מכיל זיהויים, ספירות וראיות נבחרות.
- מפתחות upload עוברים בזיכרון לתהליך קצר־חיים ואינם נשמרים בקובץ או נכללים בתשובה. אין הבטחת zeroization לזיכרון Python.
- הדמו משתמש בקבצים זמניים ליצירת תעודת בדיקה ו־key log; הם נמחקים בסיום.

## התקנה ובדיקות

קוד המקור תואם Python 3.9+. פענוח משתמש ב־cryptography במקום מימוש AES עצמאי.
מפעיל הממשק משתמש בסביבת Codex שבה התלות כבר מותקנת. בסביבה אחרת:

```sh
python3 -m pip install -r requirements-decryption.txt
python3 -B -m unittest discover -s tests -v
```

בדיקות כוללות חיבור OpenSSL עצמאי, שלוש חבילות הצפנה, החלפת מפתחות בין handshake ל־application,
padding, מפתחות חסרים/שגויים/סותרים, ciphertext ששונה, רשומות חתוכות ומקטעי TCP חסרים/סותרים.

## מקורות

- TLS 1.3 records/key schedule: https://www.rfc-editor.org/rfc/rfc8446.html (sections 5, 7.3).
- Key log format: https://www.rfc-editor.org/rfc/rfc9850.html.
- AEAD API: https://cryptography.io/en/latest/hazmat/primitives/aead/.
- NSS key logging: https://github.com/mozilla-firefox/cedar/blob/main/security/nss/doc/rst/legacy/key_log_format/index.rst.

מקורות הרחבה: RFC 5246 (PRF, key block, AEAD), RFC 5288/5289 (AES-GCM), RFC 8446 sections 4.6.3 and 7.2 (KeyUpdate).
