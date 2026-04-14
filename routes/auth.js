const router  = require('express').Router();
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const User    = require('../models/User');
const { SECRET_KEY, REFRESH_SECRET, MAX_LOGIN_ATTEMPTS, LOCK_TIME, tokenBlacklist } = require('../config/constants');

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ── POST /auth/register ───────────────────────────────────────────
router.post('/register', async (req, res) => {
  try {
    const { name, email, password, confirmPassword, role } = req.body;

    // Валідація
    if (!name || !email || !password || !confirmPassword)
      return res.status(400).json({ message: 'Всі поля обовязкові' });

    if (!emailRegex.test(email))
      return res.status(400).json({ message: 'Невірний формат email' });

    if (password.length < 6)
      return res.status(400).json({ message: 'Пароль мінімум 6 символів' });

    if (password !== confirmPassword)
      return res.status(400).json({ message: 'Паролі не співпадають' });

    // Перевірка дублювання
    const exists = await User.findOne({ where: { email } });
    if (exists)
      return res.status(400).json({ message: 'Користувач з таким email вже існує' });

    // Хешування пароля
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      email,
      password: hashedPassword,
      role: role === 'admin' ? 'admin' : 'user',
    });

    res.status(201).json({ message: 'Користувача створено', userId: user.id });
  } catch (err) {
    console.error('[REGISTER ERROR]', err.message);
    res.status(500).json({ message: 'Помилка сервера' });
  }
});

// ── POST /auth/login ──────────────────────────────────────────────
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ message: 'Email та пароль обовязкові' });

    const user = await User.findOne({ where: { email } });
    if (!user)
      return res.status(400).json({ message: 'Користувача не знайдено' });

    // Перевірка блокування
    if (user.lockedUntil && new Date() < user.lockedUntil) {
      const remaining = Math.ceil((user.lockedUntil - new Date()) / 60000);
      return res.status(429).json({ message: `Акаунт заблоковано. Спробуйте через ${remaining} хв.` });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      // Збільшити лічильник спроб
      const attempts = user.loginAttempts + 1;
      const update = { loginAttempts: attempts };
      if (attempts >= MAX_LOGIN_ATTEMPTS) {
        update.lockedUntil = new Date(Date.now() + LOCK_TIME);
        update.loginAttempts = 0;
      }
      await user.update(update);
      return res.status(400).json({ message: `Невірний пароль. Спроб залишилось: ${MAX_LOGIN_ATTEMPTS - attempts}` });
    }

    // Скинути лічильник після успішного входу
    await user.update({ loginAttempts: 0, lockedUntil: null });

    const token        = jwt.sign({ id: user.id, email: user.email, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
    const refreshToken = jwt.sign({ id: user.id, email: user.email }, REFRESH_SECRET, { expiresIn: '7d' });

    res.json({ token, refreshToken, role: user.role });
  } catch (err) {
    console.error('[LOGIN ERROR]', err.message);
    res.status(500).json({ message: 'Помилка сервера' });
  }
});

// ── POST /auth/logout ─────────────────────────────────────────────
router.post('/logout', (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
  if (token) tokenBlacklist.add(token);
  res.json({ message: 'Вихід виконано успішно' });
});

// ── POST /auth/refresh ────────────────────────────────────────────
router.post('/refresh', (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken)
    return res.status(400).json({ message: 'Refresh token відсутній' });
  try {
    const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
    const newToken = jwt.sign({ id: decoded.id, email: decoded.email, role: decoded.role }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token: newToken });
  } catch {
    res.status(401).json({ message: 'Невірний refresh token' });
  }
});

module.exports = router;
