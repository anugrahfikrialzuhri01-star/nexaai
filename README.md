# NexaAI — backend PostgreSQL

Backend ini sudah dimigrasikan dari SQLite ke PostgreSQL dan mempertahankan route login, register, chat Groq, riwayat, dan panel admin.

## Menjalankan
1. Install Node.js 20 atau lebih baru.
2. Buat database PostgreSQL (misalnya dari penyedia PostgreSQL terkelola).
3. Salin `.env.example` menjadi `.env`.
4. Isi `JWT_SECRET` dengan string acak rahasia minimal 32 karakter, `GROQ_API_KEY`, dan `DATABASE_URL` dari penyedia database.
5. Jalankan `npm install`, lalu `npm start`.
6. Buka `http://localhost:3000`.

Tabel akan dibuat otomatis saat server mulai. Untuk deploy, atur variabel lingkungan yang sama di pengaturan hosting, jangan unggah `.env`.

## Penting
- Database PostgreSQL baru tidak membawa akun dan riwayat dari database SQLite lama. Migrasi data lama belum otomatis; lakukan ekspor/impor terpisah jika data lama perlu dipertahankan.
- Akun admin yang sebelumnya tersimpan di SQLite juga tidak otomatis ikut pindah. Setelah membuat akun pertama di PostgreSQL, jadikan admin lewat SQL pada dashboard database: `UPDATE users SET role = 'admin' WHERE username = 'USERNAME_KAMU';` Ganti `USERNAME_KAMU` dengan username milikmu.
- Rate limit chat tetap 15 permintaan per menit; tidak ditambahkan kuota harian.
- Pastikan `DATABASE_URL` memakai connection string PostgreSQL yang benar. `PGSSLMODE=disable` hanya untuk database lokal yang tidak memakai SSL.
- Jangan pernah membagikan `.env`, JWT secret, password database, atau API key.
