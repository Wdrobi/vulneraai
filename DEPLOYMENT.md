# Deploy VulneraAI Frontend to GitHub Pages

This guide walks you through hosting the VulneraAI frontend on GitHub Pages.

## 📋 Prerequisites

- Your repo pushed to GitHub: `https://github.com/Wdrobi/vulneraai`
- Backend deployed separately (Render/Railway) or running locally

## 🚀 Quick Setup

### Step 1: Enable GitHub Pages

1. Go to your repo: **https://github.com/Wdrobi/vulneraai**
2. Click **Settings** → **Pages** (left sidebar)
3. Under **Source**, select:
   - **Branch:** `main`
   - **Folder:** `/frontend` (or `/docs` if you want to use docs folder)
4. Click **Save**

**Wait 2-3 minutes** for GitHub to build your site.

### Step 2: Access Your Live Site

Your frontend will be available at:
```
https://Wdrobi.github.io/vulneraai/
```

Or if you have a custom domain:
```
https://your-custom-domain.com
```

## 🔧 Update Backend URL

The frontend is pre-configured to auto-detect:
- **Local dev:** Uses `http://localhost:5000/api`
- **Production:** Uses `https://vulneraai-backend.onrender.com/api`

To change the production backend URL:

1. Open `frontend/js/api.js`
2. Update line 8:
   ```javascript
   : 'https://YOUR-BACKEND-URL.onrender.com/api';
   ```

## 🔒 Important: Backend Deployment Required

GitHub Pages only hosts **static files** (HTML/CSS/JS). You need to deploy the Flask backend separately:

### Option A: Render (Recommended)
1. Sign up at https://render.com
2. Create a new **Web Service** from your GitHub repo
3. Build command: `pip install -r backend/requirements.txt`
4. Start command: `cd backend && gunicorn app:app`
   - Uses the provided Procfile: `web: cd backend && gunicorn app:app`
5. Add environment variables (API keys, SECRET_KEY)
6. Copy the live URL (e.g., `https://vulneraai.onrender.com`)
7. Update `frontend/js/api.js` with this URL

### Option B: Railway
Similar to Render but with different UI. Follow Railway's Flask deployment guide.

## 🧪 Test Your Deployment

1. Visit `https://Wdrobi.github.io/vulneraai/`
2. Open browser DevTools (F12) → Console
3. Try to login/register
4. Check if API calls succeed or show CORS/network errors

### Common Issues

**CORS Error:**
- Your backend must allow requests from `https://Wdrobi.github.io`
- In `backend/app.py`, Flask-CORS should have:
  ```python
  CORS(app, origins=['https://Wdrobi.github.io', 'http://localhost:5000'])
  ```

**404 on API calls:**
- Backend not deployed or wrong URL in `api.js`
- Check the backend URL in browser DevTools → Network tab

**Styles not loading:**
- Check if paths are relative (e.g., `css/styles.css` not `/css/styles.css`)
- GitHub Pages serves from `/vulneraai/` not root `/`

## 📝 Custom Domain (Optional)

1. Buy a domain (Namecheap, GoDaddy, etc.)
2. Add a `CNAME` file in `frontend/` with your domain:
   ```
   vulneraai.example.com
   ```
3. Configure DNS records at your domain provider:
   - Add CNAME record pointing to `Wdrobi.github.io`
4. In GitHub Pages settings, add your custom domain

## 🔄 Updates

Every time you push changes to `main` branch → `frontend/` folder, GitHub Pages auto-rebuilds (takes 1-3 min).

To force rebuild:
```bash
git commit --allow-empty -m "Trigger GitHub Pages rebuild"
git push origin main
```

## ✅ Checklist

- [ ] GitHub Pages enabled on `/frontend` folder
- [ ] Backend deployed on Render/Railway
- [ ] `api.js` updated with live backend URL
- [ ] CORS configured in backend to allow GitHub Pages domain
- [ ] Tested login/scan from live site

---

**Live Site:** https://Wdrobi.github.io/vulneraai/  
**Backend:** Deploy separately (see main README)
