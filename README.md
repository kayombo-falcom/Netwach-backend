# Netwatch — Backend API

> Django backend for the Netwatch network monitoring dashboard.

![Python](https://img.shields.io/badge/Python-3-3776AB?logo=python&logoColor=white)
![Django](https://img.shields.io/badge/Django-6.1-092E20?logo=django&logoColor=white)
![Status](https://img.shields.io/badge/status-early_stage-orange)

This service will store and serve network data (devices, users, access points, traffic and alerts) for the [Netwatch frontend](https://github.com/kayombo-falcom/Netwatch-frontend).

## 🗺 Roadmap

- [x] Django project setup
- [ ] Models: devices, users, access points, traffic, alerts, policies
- [ ] REST API for the dashboard
- [ ] Authentication and roles
- [ ] Live data collection from access points

## 🚀 Getting Started

```bash
git clone https://github.com/kayombo-falcom/Netwach-backend.git
cd Netwach-backend
python -m venv venv
venv\Scripts\activate        # Windows  (macOS/Linux: source venv/bin/activate)
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver   # http://127.0.0.1:8000
```

## 📁 Structure

```
netwatch_backend/   # settings, urls, asgi, wsgi
manage.py           # Django CLI
requirements.txt    # dependencies
```

## 👤 Author

**Hirorims Kayombo** · [Portfolio](https://hirorims.netlify.app/) · [GitHub](https://github.com/kayombo-falcom)
