import crypto from 'node:crypto';
import dotenv from 'dotenv';
import express from 'express';

dotenv.config();

const app = express();
const port = Number(process.env.PORT || 3000);
const clientId = process.env.DISCORD_CLIENT_ID;
const clientSecret = process.env.DISCORD_CLIENT_SECRET;
const redirectUri = process.env.DISCORD_REDIRECT_URI || `http://localhost:${port}/auth/discord/callback`;
const discordUserId = '1542616256967082085';
const cookieKey = crypto.createHash('sha256').update(clientSecret || '').digest();

function getCookies(request) {
  return Object.fromEntries((request.headers.cookie || '').split(';').filter(Boolean).map((item) => {
    const [key, ...value] = item.trim().split('=');
    return [key, value.join('=')];
  }));
}

function sealSession(session) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', cookieKey, iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(session), 'utf8'), cipher.final()]);
  const payload = Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString('base64url');
  return payload;
}

function openSession(value) {
  try {
    const payload = Buffer.from(value, 'base64url');
    const decipher = crypto.createDecipheriv('aes-256-gcm', cookieKey, payload.subarray(0, 12));
    decipher.setAuthTag(payload.subarray(12, 28));
    return JSON.parse(Buffer.concat([decipher.update(payload.subarray(28)), decipher.final()]).toString('utf8'));
  } catch {
    return null;
  }
}

function setSessionCookie(response, session) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  response.setHeader('Set-Cookie', `profile_session=${sealSession(session)}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax${secure}`);
}

if (!clientId || !clientSecret) {
  console.error('Missing DISCORD_CLIENT_ID or DISCORD_CLIENT_SECRET in .env');
  process.exit(1);
}

app.get('/', (request, response, next) => {
  const cookies = getCookies(request);
  if (!openSession(cookies.profile_session || '')) return response.redirect('/auth/discord');
  next();
});

app.use(express.static('.'));

app.get('/auth/discord', (request, response) => {
  const state = crypto.randomBytes(24).toString('hex');
  response.setHeader('Set-Cookie', `oauth_state=${state}; Path=/; HttpOnly; SameSite=Lax`);
  const params = new URLSearchParams({
    client_id: clientId,
    response_type: 'code',
    redirect_uri: redirectUri,
    scope: 'identify',
    state
  });
  response.redirect(`https://discord.com/oauth2/authorize?${params}`);
});

app.get('/auth/discord/callback', async (request, response) => {
  const { code, state } = request.query;
  const cookies = getCookies(request);
  if (!code || !state || state !== cookies.oauth_state) return response.status(400).send('Invalid Discord authorization state.');

  try {
    const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri
      })
    });
    if (!tokenResponse.ok) throw new Error('Discord token exchange failed.');

    const token = await tokenResponse.json();
    const userResponse = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${token.access_token}` }
    });
    if (!userResponse.ok) throw new Error('Discord profile request failed.');

    const user = await userResponse.json();
    setSessionCookie(response, {
      accessToken: token.access_token,
      refreshToken: token.refresh_token,
      expiresAt: Date.now() + (token.expires_in * 1000),
      id: user.id,
      username: user.global_name || user.username,
      avatar: user.avatar
        ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=256`
        : null
    });
    response.redirect('/');
  } catch (error) {
    console.error(error.message);
    response.status(502).send('Unable to load the Discord profile.');
  }
});

app.get('/api/me', async (request, response) => {
  const cookies = getCookies(request);
  const session = openSession(cookies.profile_session || '');
  if (!session) return response.json(null);

  try {
    if (session.expiresAt <= Date.now() + 60000 && session.refreshToken) {
      const refreshResponse = await fetch('https://discord.com/api/oauth2/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: clientId,
          client_secret: clientSecret,
          grant_type: 'refresh_token',
          refresh_token: session.refreshToken
        })
      });
      if (refreshResponse.ok) {
        const refreshed = await refreshResponse.json();
        session.accessToken = refreshed.access_token;
        session.refreshToken = refreshed.refresh_token || session.refreshToken;
        session.expiresAt = Date.now() + (refreshed.expires_in * 1000);
        setSessionCookie(response, session);
      }
    }
    const userResponse = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${session.accessToken}` }
    });
    if (userResponse.ok) {
      const user = await userResponse.json();
      session.id = user.id;
      session.username = user.global_name || user.username;
      session.avatar = user.avatar
        ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=256`
        : null;
    }
  } catch (error) {
    console.error('Discord sync failed:', error.message);
  }

  response.json({ id: session.id, username: session.username, avatar: session.avatar });
});

app.get('/api/activity', async (request, response) => {
  try {
    const activityResponse = await fetch(`https://api.lanyard.rest/v1/users/${discordUserId}`);
    if (!activityResponse.ok) return response.status(404).json({ available: false });
    const payload = await activityResponse.json();
    response.json({ available: true, ...payload.data });
  } catch (error) {
    console.error('Activity sync failed:', error.message);
    response.status(502).json({ available: false });
  }
});

app.listen(port, () => {
  console.log(`Profile server running at http://localhost:${port}`);
});
