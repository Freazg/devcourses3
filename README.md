# DevCourses — ЛР №3: REST API + Auth + JWT

**Автор:** Сас Євгеній Олександрович, група ІО-31
Дисципліна: WEB-орієнтовані технології. Backend розробки
КПІ ім. Ігоря Сікорського, ФІОТ, кафедра ІСТ

## Структура

```
lab3/
├── config/
│   ├── database.js      # Sequelize підключення
│   └── constants.js     # SECRET_KEY, blacklist, обмеження
├── middleware/
│   └── auth.js          # JWT middleware + перевірка ролі
├── models/
│   └── User.js          # Sequelize модель користувача
├── routes/
│   ├── auth.js          # /register, /login, /logout, /refresh
│   └── users.js         # /profile, /change-password, /delete
├── server.js
└── package.json
```

## Запуск

```bash
npm install
# вказати пароль MySQL у config/database.js
npm start   # → http://localhost:3002
```

## API

| Метод  | URL                       | Auth  | Опис                          |
|--------|---------------------------|-------|-------------------------------|
| POST   | /auth/register            | —     | Реєстрація                    |
| POST   | /auth/login               | —     | Вхід → access + refresh token |
| POST   | /auth/logout              | —     | Вихід (blacklist токена)      |
| POST   | /auth/refresh             | —     | Оновити access token          |
| GET    | /users/profile            | JWT   | Переглянути профіль           |
| PUT    | /users/profile            | JWT   | Оновити профіль               |
| PUT    | /users/change-password    | JWT   | Змінити пароль                |
| DELETE | /users/profile            | JWT   | Видалити акаунт               |
| GET    | /users                    | admin | Всі користувачі               |
| DELETE | /users/:id                | admin | Видалити користувача          |
