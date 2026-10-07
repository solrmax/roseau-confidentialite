const config = {"name":"Roseau","url":"https://ymkuxfjplppvgtliibuy.supabase.co","key":"sb_publishable_JC6PaVwnJJ9ZjzlSeEzpnQ_TJ0HnnVt","redirect":"https://solrmax.github.io/roseau-confidentialite/suppression.html"};
const byId = id => document.getElementById(id);
const status = text => { byId('status').textContent = text; };
// Only the one-use PKCE verifier survives the Google redirect, in this tab.
const verifierKey = config.name.toLowerCase() + '-deletion-verifier';
const base64url = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
let session = null;
let busy = false;
let timer;
const redirectTo = config.redirect;
const reset = async () => {
  session = null;
  clearTimeout(timer);
  byId('confirmation').hidden = true;
  byId('login').hidden = false;
  byId('confirm').value = '';
  byId('delete').disabled = true;
  sessionStorage.removeItem(verifierKey);
};
byId('login').addEventListener('click', async () => {
  byId('login').disabled = true;
  status('Ouverture de la connexion Google…');
  try {
    await reset();
    const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
    const challenge = base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
    sessionStorage.setItem(verifierKey, JSON.stringify({ verifier, startedAt: Date.now() }));
    const authUrl = new URL(config.url + '/auth/v1/authorize');
    authUrl.search = new URLSearchParams({ provider: 'google', redirect_to: redirectTo, code_challenge: challenge, code_challenge_method: 's256', prompt: 'select_account' });
    location.assign(authUrl.href);
  } catch { status('Connexion indisponible. Réessayez dans quelques instants.'); byId('login').disabled = false; }
});
byId('cancel').addEventListener('click', async () => { if (busy) return; await reset(); status('Annulé. Aucune suppression effectuée.'); });
byId('confirm').addEventListener('input', () => { byId('delete').disabled = busy || !session || byId('confirm').value !== 'SUPPRIMER'; });
byId('delete').addEventListener('click', async () => {
  if (busy || !session || byId('confirm').value !== 'SUPPRIMER') return;
  busy = true;
  byId('delete').disabled = true;
  byId('cancel').disabled = true;
  status('Suppression en cours…');
  try {
    const response = await fetch(config.url + '/functions/v1/delete-web-account', {
      method: 'POST', credentials: 'omit', cache: 'no-store',
      headers: { authorization: 'Bearer ' + session.access_token, apikey: config.key, 'content-type': 'application/json' },
      body: JSON.stringify({ confirm: 'SUPPRIMER' }), signal: AbortSignal.timeout(45000),
    });
    const data = await response.json();
    if (!response.ok || data.deleted !== true) throw new Error();
    await reset();
    byId('login').hidden = true;
    status('Votre compte ' + config.name + ' et ses données en ligne ont été supprimés. Les données locales de vos appareils restent à effacer depuis les réglages de l’application.');
  } catch {
    await reset();
    status('La suppression n’a pas été confirmée. Reconnectez-vous pour vérifier et réessayer.');
  } finally { busy = false; byId('cancel').disabled = false; }
});
async function callback() {
  const params = new URLSearchParams(location.search);
  const code = params.get('code');
  const hasError = params.has('error') || location.hash.length > 0;
  history.replaceState(null, '', location.pathname);
  if (!code && !hasError) { sessionStorage.removeItem(verifierKey); return; }
  try {
    const pending = JSON.parse(sessionStorage.getItem(verifierKey) || 'null');
    sessionStorage.removeItem(verifierKey);
    if (location.origin + location.pathname !== redirectTo || hasError || !pending
      || !/^[A-Za-z0-9_-]{43}$/.test(pending.verifier) || Date.now() - pending.startedAt > 300000
      || pending.startedAt > Date.now()) throw new Error();
    status('Vérification du compte…');
    const response = await fetch(config.url + '/auth/v1/token?grant_type=pkce', {
      method: 'POST', credentials: 'omit', cache: 'no-store',
      headers: { apikey: config.key, 'content-type': 'application/json' },
      body: JSON.stringify({ auth_code: code, code_verifier: pending.verifier }),
      signal: AbortSignal.timeout(15000),
    });
    const data = await response.json();
    if (!response.ok || typeof data.access_token !== 'string') throw new Error();
    const verification = await fetch(config.url + '/auth/v1/user', {
      credentials: 'omit', cache: 'no-store',
      headers: { apikey: config.key, authorization: 'Bearer ' + data.access_token },
      signal: AbortSignal.timeout(15000),
    });
    const user = await verification.json();
    if (!verification.ok || !user?.email) throw new Error();
    session = { access_token: data.access_token };
    byId('email').textContent = user.email;
    byId('login').hidden = true;
    byId('confirmation').hidden = false;
    status('Compte vérifié. La connexion seule ne supprime rien.');
    timer = setTimeout(async () => { if (!busy) { await reset(); status('La confirmation a expiré. Reconnectez-vous pour continuer.'); } }, 240000);
  } catch { await reset(); status('Connexion expirée ou invalide. Recommencez avec le bouton Google ci-dessous.'); }
}
window.addEventListener('pagehide', () => { session = null; });
if (window.top !== window.self) { byId('login').disabled = true; status('Ouvrez cette page directement dans votre navigateur.'); }
else callback();
