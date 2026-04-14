const jwt = require('jsonwebtoken');
const { SECRET_KEY, tokenBlacklist } = require('../config/constants');

// ── Перевірка JWT токена ──────────────────────────────────────────
function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ')
    ? authHeader.slice(7)
    : authHeader;

  if (!token) {
    return res.status(401).json({ message: 'Токен відсутній. Авторизуйтесь.' });
  }

  if (tokenBlacklist.has(token)) {
    return res.status(401).json({ message: 'Токен анульовано. Увійдіть знову.' });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user  = decoded;
    req.token = token;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Невірний або прострочений токен.' });
  }
}

// ── Перевірка ролі адміна ─────────────────────────────────────────
function adminMiddleware(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Доступ заборонено. Потрібна роль admin.' });
  }
  next();
}

module.exports = { authMiddleware, adminMiddleware };
