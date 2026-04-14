const SECRET_KEY     = 'devcourses_secret_2026';
const REFRESH_SECRET = 'devcourses_refresh_2026';
const MAX_LOGIN_ATTEMPTS = 5;      // макс. спроб входу
const LOCK_TIME = 15 * 60 * 1000; // 15 хвилин блокування

// In-memory blacklist для logout (у продакшн — Redis)
const tokenBlacklist = new Set();

module.exports = { SECRET_KEY, REFRESH_SECRET, MAX_LOGIN_ATTEMPTS, LOCK_TIME, tokenBlacklist };
