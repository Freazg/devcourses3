const express   = require('express');
const sequelize = require('./config/database');
const User      = require('./models/User');
const authRoutes  = require('./routes/auth');
const userRoutes  = require('./routes/users');

const app  = express();
const PORT = 3002;

app.use(express.json());

// ── Маршрути ──────────────────────────────────────────────────────
app.use('/auth',  authRoutes);
app.use('/users', userRoutes);

// ── Головна ───────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({
    message: 'DevCourses Auth API',
    endpoints: {
      'POST /auth/register':          'Реєстрація',
      'POST /auth/login':             'Вхід → JWT токен',
      'POST /auth/logout':            'Вихід (анулювання токена)',
      'POST /auth/refresh':           'Оновлення access токена',
      'GET  /users/profile':          'Профіль (захищено)',
      'PUT  /users/profile':          'Оновити профіль (захищено)',
      'PUT  /users/change-password':  'Змінити пароль (захищено)',
      'DELETE /users/profile':        'Видалити акаунт (захищено)',
      'GET  /users':                  'Всі користувачі (admin)',
      'DELETE /users/:id':            'Видалити юзера (admin)',
    },
  });
});

// ── Глобальна обробка 404 ─────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ message: `Маршрут ${req.method} ${req.path} не знайдено` });
});

// ── Глобальна обробка помилок ─────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[SERVER ERROR]', err.message);
  res.status(500).json({ message: 'Внутрішня помилка сервера' });
});

// ── Синхронізація БД та запуск ────────────────────────────────────
sequelize.authenticate()
  .then(() => console.log('MySQL підключено'))
  .catch(err => { console.error('Помилка підключення:', err); process.exit(1); });

sequelize.sync()
  .then(() => console.log('Таблицю Users синхронізовано'))
  .catch(err => console.error('Помилка синхронізації:', err));

app.listen(PORT, () => {
  console.log(`DevCourses Auth API: http://localhost:${PORT}`);
});
