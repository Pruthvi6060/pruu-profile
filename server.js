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
const sessions = new Map();

function getCookies(request) {
  return Object.fromEntries((request.headers.cookie || '').split(';').filter(Boolean).map((item) => {
    const [key, ...value] = item.trim().split('=');
    return [key, value.join('=')];
  }));
}

if (!clientId || !clientSecret) {
  console.error('Missing DISCORD_CLIENT_ID or DISCORD_CLIENT_SECRET in .env');
  process.exit(1);
}

app.get('/', (request, response, next) => {
  const cookies = getCookies(request);
  if (!sessions.has(cookies.profile_session)) return response.redirect('/auth/discord');
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
    const sessionId = crypto.randomBytes(32).toString('hex');
    sessions.set(sessionId, {
      accessToken: token.access_token,
      id: user.id,
      username: user.global_name || user.username,
      avatar: user.avatar
        ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=256`
        : null
    });
    response.setHeader('Set-Cookie', `profile_session=${sessionId}; Path=/; HttpOnly; SameSite=Lax`);
    response.redirect('/');
  } catch (error) {
    console.error(error.message);
    response.status(502).send('Unable to load the Discord profile.');
  }
});

app.get('/api/me', async (request, response) => {
  const cookies = getCookies(request);
  const session = sessions.get(cookies.profile_session);
  if (!session) return response.json(null);

  try {
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
