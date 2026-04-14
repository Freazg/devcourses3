const router = require('express').Router();
const bcrypt = require('bcryptjs');
const User   = require('../models/User');
const { authMiddleware, adminMiddleware } = require('../middleware/auth');

// ── GET /users/profile — власний профіль ─────────────────────────
router.get('/profile', authMiddleware, async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id, {
      attributes: { exclude: ['password', 'loginAttempts', 'lockedUntil'] },
    });
    if (!user) return res.status(404).json({ message: 'Користувача не знайдено' });
    res.json(user);
  } catch (err) {
    console.error('[PROFILE ERROR]', err.message);
    res.status(500).json({ message: 'Помилка сервера' });
  }
});

// ── PUT /users/profile — оновлення профілю ───────────────────────
router.put('/profile', authMiddleware, async (req, res) => {
  try {
    const { name, email } = req.body;
    const user = await User.findByPk(req.user.id);
    if (!user) return res.status(404).json({ message: 'Користувача не знайдено' });

    if (email && email !== user.email) {
      const exists = await User.findOne({ where: { email } });
      if (exists) return res.status(400).json({ message: 'Email вже використовується' });
    }

    await user.update({ name: name || user.name, email: email || user.email });
    res.json({ message: 'Профіль оновлено', user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    console.error('[UPDATE PROFILE ERROR]', err.message);
    res.status(500).json({ message: 'Помилка сервера' });
  }
});

// ── PUT /users/change-password — зміна пароля ────────────────────
router.put('/change-password', authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body;

    if (!currentPassword || !newPassword || !confirmPassword)
      return res.status(400).json({ message: 'Всі поля обовязкові' });

    if (newPassword.length < 6)
      return res.status(400).json({ message: 'Новий пароль мінімум 6 символів' });

    if (newPassword !== confirmPassword)
      return res.status(400).json({ message: 'Нові паролі не співпадають' });

    const user = await User.findByPk(req.user.id);
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch)
      return res.status(400).json({ message: 'Поточний пароль невірний' });

    await user.update({ password: await bcrypt.hash(newPassword, 10) });
    res.json({ message: 'Пароль змінено успішно' });
  } catch (err) {
    console.error('[CHANGE PASSWORD ERROR]', err.message);
    res.status(500).json({ message: 'Помилка сервера' });
  }
});

// ── DELETE /users/profile — видалення власного акаунту ───────────
router.delete('/profile', authMiddleware, async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id);
    if (!user) return res.status(404).json({ message: 'Користувача не знайдено' });
    await user.destroy();
    res.json({ message: 'Акаунт видалено' });
  } catch (err) {
    console.error('[DELETE USER ERROR]', err.message);
    res.status(500).json({ message: 'Помилка сервера' });
  }
});

// ── GET /users — список всіх (тільки admin) ──────────────────────
router.get('/', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const users = await User.findAll({
      attributes: { exclude: ['password', 'loginAttempts', 'lockedUntil'] },
    });
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: 'Помилка сервера' });
  }
});

// ── DELETE /users/:id — видалення юзера адміном ──────────────────
router.delete('/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const user = await User.findByPk(req.params.id);
    if (!user) return res.status(404).json({ message: 'Користувача не знайдено' });
    await user.destroy();
    res.json({ message: `Користувача id=${req.params.id} видалено` });
  } catch (err) {
    res.status(500).json({ message: 'Помилка сервера' });
  }
});

module.exports = router;
