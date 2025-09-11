import express from 'express';
import session from 'express-session';
import cors from 'cors';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import Joi from 'joi';
import { google } from 'googleapis';

dotenv.config();

const app = express();
const port = process.env.PORT || 4000;
const sessionSecret = process.env.SESSION_SECRET || 'dev_secret';
const isProd = process.env.NODE_ENV === 'production';
const FRONTEND_ORIGINS = [
  'http://localhost:5173',
  'https://bridgeloyaltydashboard.netlify.app'
];

app.use(morgan('dev'));
app.use(cors({ origin: FRONTEND_ORIGINS, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(
  session({
    name: 'gsd.sid',
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: isProd, // require HTTPS in production
      sameSite: isProd ? 'none' : 'lax'
    }
  })
);
app.set('trust proxy', 1);

function getOAuthClient(req) {
  let cfg = req?.session?.clientConfig;
  // Fallback to cookie if session missing
  if (!cfg && req.cookies && req.cookies.client_config) {
    try { cfg = JSON.parse(req.cookies.client_config); } catch {}
  }
  const clientId = cfg?.clientId || process.env.GOOGLE_CLIENT_ID;
  const clientSecret = cfg?.clientSecret || process.env.GOOGLE_CLIENT_SECRET;
  const redirectUri = cfg?.redirectUri || process.env.GOOGLE_REDIRECT_URI;
  return new google.auth.OAuth2({ clientId, clientSecret, redirectUri });
}

const OAUTH_SCOPES = [
  'https://www.googleapis.com/auth/drive.metadata.readonly',
  'https://www.googleapis.com/auth/spreadsheets.readonly',
  'openid',
  'email',
  'profile'
];

function ensureAuthed(req, res, next) {
  if (req.session.tokens) return next();
  // Fallback: try to hydrate session from tokens cookie
  if (req.cookies && req.cookies.tokens) {
    try {
      const t = JSON.parse(req.cookies.tokens);
      if (t && typeof t === 'object') {
        req.session.tokens = t;
        return next();
      }
    } catch (_e) {}
  }
  return res.status(401).json({ error: 'Unauthorized' });
}

async function getAuthedClients(tokens, req) {
  const client = getOAuthClient(req);
  client.setCredentials(tokens);
  // google-auth-library will refresh using refresh_token when needed.
  const drive = google.drive({ version: 'v3', auth: client });
  const sheets = google.sheets({ version: 'v4', auth: client });
  const oauth2 = google.oauth2({ version: 'v2', auth: client });
  return { client, drive, sheets, oauth2 };
}

app.get('/auth/login', (req, res) => {
  const client = getOAuthClient(req);
  const url = client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: OAUTH_SCOPES
  });
  res.redirect(url);
});

app.get('/auth/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).send('Missing code');
  try {
    const client = getOAuthClient(req);
    const { tokens } = await client.getToken(String(code));
    req.session.tokens = tokens;
    // Persist tokens in a secure cookie to survive serverless restarts
    res.cookie('tokens', JSON.stringify(tokens), {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? 'none' : 'lax',
      // 30 days
      maxAge: 30 * 24 * 60 * 60 * 1000
    });
    const redirectTo = process.env.POST_LOGIN_REDIRECT || 'https://bridgeloyaltydashboard.netlify.app/';
    res.redirect(redirectTo);
  } catch (e) {
    console.error(e);
    res.status(500).send('OAuth callback failed');
  }
});

// Configure per-user OAuth client credentials (stored in session)
app.get('/auth/client-config', (req, res) => {
  let cfg = req.session.clientConfig;
  if (!cfg && req.cookies && req.cookies.client_config) {
    try { cfg = JSON.parse(req.cookies.client_config); } catch {}
  }
  const present = Boolean(cfg?.clientId && cfg?.clientSecret);
  res.json({ configured: present, config: present ? { redirectUri: cfg.redirectUri } : null });
});

app.post('/auth/client-config', (req, res) => {
  const schema = Joi.object({
    clientId: Joi.string().min(10).required(),
    clientSecret: Joi.string().min(10).required(),
    redirectUri: Joi.string()
      .uri()
      .optional()
      .allow('')
      .default(process.env.GOOGLE_REDIRECT_URI || 'https://server-test-liart.vercel.app/auth/callback')
  });
  const { value, error } = schema.validate(req.body || {}, { stripUnknown: true });
  if (error) return res.status(400).json({ error: error.message });
  const redirectUri = value.redirectUri && value.redirectUri.length > 0
    ? value.redirectUri
    : (process.env.GOOGLE_REDIRECT_URI || 'https://server-test-liart.vercel.app/auth/callback');
  const cfg = { clientId: value.clientId, clientSecret: value.clientSecret, redirectUri };
  req.session.clientConfig = cfg;
  // Persist client config in a secure cookie for resilience on serverless
  res.cookie('client_config', JSON.stringify(cfg), {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax'
  });
  res.json({ ok: true, redirectUri });
});

// Friendly root in case user opens API root directly
app.get('/', (_req, res) => {
  const ui = process.env.POST_LOGIN_REDIRECT || 'https://bridgeloyaltydashboard.netlify.app/';
  res.status(200).send(`OK. Open the UI at <a href="${ui}">${ui}</a>.`);
});

app.get('/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('gsd.sid');
    res.clearCookie('tokens');
    res.clearCookie('client_config');
    res.redirect('/');
  });
});

app.get('/api/me', ensureAuthed, async (req, res) => {
  try {
    const { oauth2 } = await getAuthedClients(req.session.tokens, req);
    const me = await oauth2.userinfo.get();
    res.json({
      id: me.data.id,
      name: me.data.name,
      email: me.data.email,
      photo: me.data.picture
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to fetch user info' });
  }
});

app.get('/api/sheets', ensureAuthed, async (req, res) => {
  const schema = Joi.object({
    page: Joi.number().integer().min(1).default(1),
    pageSize: Joi.number().integer().min(1).max(50).default(12),
    query: Joi.string().allow('').default('')
  });
  const { value, error } = schema.validate(req.query);
  if (error) return res.status(400).json({ error: error.message });
  const { page, pageSize, query } = value;

  try {
    const { drive, sheets } = await getAuthedClients(req.session.tokens, req);
    const driveParams = {
      q: `mimeType='application/vnd.google-apps.spreadsheet' and trashed=false${query ? ` and name contains '${query.replace(/'/g, "\\'")}'` : ''}`,
      pageSize,
      fields: 'files(id,name,owners,modifiedTime),nextPageToken',
      orderBy: 'modifiedTime desc'
    };
    let pageToken = undefined;
    for (let i = 1; i < page; i++) {
      const r = await drive.files.list({ ...driveParams, pageToken });
      pageToken = r.data.nextPageToken;
      if (!pageToken) break;
    }
    const resp = await drive.files.list({ ...driveParams, pageToken });
    const files = resp.data.files || [];

    const items = files.map((f) => ({
      id: f.id,
      name: f.name,
      owners: (f.owners || []).map((o) => o.displayName).filter(Boolean),
      modifiedTime: f.modifiedTime
    }));

    // Note: Drive API doesn't return a total count; we report current page size.
    res.json({ items, total: items.length });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to list sheets' });
  }
});

app.post('/api/sheets/:id/refresh', ensureAuthed, async (req, res) => {
  // No server-side cache yet; endpoint exists for parity
  res.json({ ok: true });
});

// Return inner sheets (tabs) with a small preview for each
app.get('/api/sheets/:id/tabs', ensureAuthed, async (req, res) => {
  const spreadsheetId = req.params.id;
  try {
    const { sheets } = await getAuthedClients(req.session.tokens, req);

    // Fetch sheet metadata (titles and ids)
    const meta = await sheets.spreadsheets.get({
      spreadsheetId,
      fields: 'sheets(properties(sheetId,title,index))'
    });
    const sheetProps = (meta.data.sheets || []).map((s) => s.properties).filter(Boolean);

    if (sheetProps.length === 0) return res.json({ items: [] });

    // Build ranges for batchGet limited to A1:E3 per sheet
    const ranges = sheetProps.map((p) => `'${String(p.title).replace(/'/g, "''")}'!A1:E3`);
    let valuesByIndex = [];
    try {
      const batch = await sheets.spreadsheets.values.batchGet({ spreadsheetId, ranges });
      valuesByIndex = batch.data.valueRanges || [];
    } catch (e) {
      valuesByIndex = [];
    }

    const items = sheetProps.map((p) => ({
      title: p.title,
      gid: p.sheetId
    }));

    res.json({ items });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to fetch inner sheets' });
  }
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal Server Error' });
});

app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
});


