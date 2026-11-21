/** Every user-facing message the kit sends. Apps may reuse these for consistency. */
export const MESSAGES = {
  invalidToken: "Sesi tidak valid atau telah berakhir",
  invalidCredentials: "Username atau password salah",
  forbidden: "Anda tidak memiliki akses",
  notFound: "Endpoint tidak ditemukan",
  validation: "Data tidak valid",
  internal: "Terjadi kesalahan pada server",
  authUnavailable: "Layanan autentikasi sedang tidak tersedia",
  notReady: "Layanan belum siap",
  fileTooLarge: "Ukuran file melebihi batas",
  fileTypeNotAllowed: "Tipe file tidak diizinkan",
} as const;
