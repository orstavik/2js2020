// _globals
//   SECRET
//   SESSION_ROOT
//   STATE_PARAM_TTL
//   SESSION_TTL
//   KV_AUTH
//......
//   SESSION_COOKIE_NAME
//   GOOGLE_CLIENTID
//   GOOGLE_CLIENTSECRET
//   GOOGLE_CODE_LINK
//   GOOGLE_OAUTH_LINK
//   GOOGLE_REDIRECT
//   GITHUB_CLIENTID
//   GITHUB_CLIENTSECRET
//   GITHUB_CODE_LINK
//   GITHUB_OAUTH_LINK
//   GITHUB_REDIRECT
//   COUNTER_DOMAIN
//   COUNTER_KEY

let cachedPassHash;

//imported pure functions begins
function randomString(length) {
  const iv = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(iv).map(b => ('00' + b.toString(16)).slice(-2)).join('');
}

function getCookieValue(cookie, key) {
  return cookie?.match(`(^|;)\\s*${key}\\s*=\\s*([^;]+)`)?.pop();
}

function bakeCookie(name, value, domain, ttl) {
  let cookie = `${name}=${value}; HttpOnly; Secure; SameSite=Strict; Path=/; Domain=${domain};`;
  if (ttl !== '')
    cookie += 'Max-age=' + ttl;
  return cookie;
}

function uint8ToHexString(ar) {
  return Array.from(ar).map(b => ('00' + b.toString(16)).slice(-2)).join('');
}

function hexStringToUint8(str) {
  return new Uint8Array(str.match(/.{2}/g).map(byte => parseInt(byte, 16)));
}

function toBase64url(base64str) {
  return base64str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function fromBase64url(base64urlStr) {
  base64urlStr = base64urlStr.replace(/-/g, '+').replace(/_/g, '/');
  if (base64urlStr.length % 4 === 2)
    return base64urlStr + '==';
  if (base64urlStr.length % 4 === 3)
    return base64urlStr + '=';
  return base64urlStr;
}

async function passHash(pw) {
  return cachedPassHash || (cachedPassHash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pw)));
}

async function makeKeyAESGCM(password, iv) {
  const pwHash = await passHash(password);
  const alg = {name: 'AES-GCM', iv: iv};                            // specify algorithm to use
  return await crypto.subtle.importKey('raw', pwHash, alg, false, ['decrypt', 'encrypt']);  // use pw to generate key
}

async function encryptAESGCM(password, iv, plaintext) {
  const key = await makeKeyAESGCM(password, iv);
  const ptUint8 = new TextEncoder().encode(plaintext);                               // encode plaintext as UTF-8
  const ctBuffer = await crypto.subtle.encrypt({name: key.algorithm.name, iv: iv}, key, ptUint8);                   // encrypt plaintext using key
  const ctArray = Array.from(new Uint8Array(ctBuffer));                              // ciphertext as byte array
  return ctArray.map(byte => String.fromCharCode(byte)).join('');             // ciphertext as string
}

async function decryptAESGCM(password, iv, ctStr) {
  const key = await makeKeyAESGCM(password, iv);
  const ctUint8 = new Uint8Array(ctStr.match(/[\s\S]/g).map(ch => ch.charCodeAt(0))); // ciphertext as Uint8Array
  const plainBuffer = await crypto.subtle.decrypt({name: key.algorithm.name, iv: iv}, key, ctUint8);                 // decrypt ciphertext using key
  return new TextDecoder().decode(plainBuffer);                                       // return the plaintext
}

async function encryptData(data, password) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await encryptAESGCM(password, iv, data);
  return uint8ToHexString(iv) + '.' + toBase64url(btoa(cipher));
}

async function decryptData(data, password) {
  const [ivText, cipherB64url] = data.split('.');
  const iv = hexStringToUint8(ivText);
  const cipher = atob(fromBase64url(cipherB64url));
  return await decryptAESGCM(password, iv, cipher);
}

function checkTTL(iat, ttl) {
  const now = Date.now();
  const stillTimeToLive = now < iat + ttl;
  const notAFutureDream = iat < now;
  return stillTimeToLive && notAFutureDream;
}

//imported pure functions ends

//imported authentication functions
function redirect(path, params) {
  return Response.redirect(path + '?' + Object.entries(params).map(([k, v]) => k + '=' + encodeURIComponent(v)).join('&'));
}

async function fetchAccessToken(path, data) {
  return await fetch(path, {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: Object.entries(data).map(([k, v]) => k + '=' + encodeURIComponent(v)).join('&')
  });
}

async function googleProcessTokenPackage(code) {
  const tokenPackage = await fetchAccessToken(
    GOOGLE_CODE_LINK, {
      code,
      client_id: GOOGLE_CLIENTID,
      client_secret: GOOGLE_CLIENTSECRET,
      redirect_uri: GOOGLE_REDIRECT,
      grant_type: 'authorization_code'
    }
  );
  const jwt = await tokenPackage.json();
  const [header, payloadB64url, signature] = jwt.id_token.split('.');
  const payloadText = atob(fromBase64url(payloadB64url));
  const payload = JSON.parse(payloadText);
  return ['go' + payload.sub, payload.email];
}

async function githubProcessTokenPackage(code, state) {
  const accessTokenPackage = await fetchAccessToken(GITHUB_CODE_LINK, {
    code,
    client_id: GITHUB_CLIENTID,
    client_secret: GITHUB_CLIENTSECRET,
    redirect_uri: GITHUB_REDIRECT,
    state
  });
  const data = await accessTokenPackage.text();
  const x = {};
  data.split('&').map(pair => pair.split('=')).forEach(([k, v]) => x[k] = v);
  const accessToken = x['access_token'];
  const user = await fetch('https://api.github.com/user', {
    headers: {
      'Authorization': 'token ' + accessToken,
      'User-Agent': '2js-no',
      'Accept': 'application/vnd.github.v3+json'
    }
  });
  const userData = await user.json();
  return ['gi' + userData.id, 'github.com/' + userData.name];
}

//imported counter
const hitCounter = `https://api.countapi.xyz/hit/${SESSION_ROOT}/${COUNTER_KEY}`;

async function count() {
  const nextCount = await fetch(hitCounter);
  const data = await nextCount.json();
  return data.value;
}

//imported counter ends

//imported authentication functions ends

async function handleRequest(request) {
  const url = new URL(request.url);
  const [ignore, action, data] = url.pathname.split('/');

  if (action === 'login') {
    const rm = url.searchParams.get('remember-me');
    const state = await encryptData(JSON.stringify({
      iat: Date.now(),
      ttl: STATE_PARAM_TTL,
      rm,
      provider: data
    }), SECRET);
    if (data === 'github')
      return redirect(GITHUB_OAUTH_LINK, {
        state,
        client_id: GITHUB_CLIENTID,
        redirect_url: GITHUB_REDIRECT,
        scope: 'user'
      });
    if (data === 'google')
      return redirect(GOOGLE_OAUTH_LINK, {
        state,
        nonce: randomString(12),
        client_id: GOOGLE_CLIENTID,
        redirect_uri: GOOGLE_REDIRECT,
        scope: 'openid email',
        response_type: 'code',
      });
    throw 'Login with correct provider: ' + data;
  }

  if (action === 'callback') {
    let state;
    try {
      const stateSecret = url.searchParams.get('state');
      const stateTxt = await decryptData(stateSecret, SECRET);

      state = JSON.parse(stateTxt);
      if (!state && !checkTTL(state.iat, state.ttl))
        return new Response('Login session timed out.', {status: 401});
    } catch (err) {
      throw 'callback without ILLEGAL stateSecret';
    }
    const code = url.searchParams.get('code');
    console.log(state.provider, data)
    let providerId, username;
    if (state.provider === data && data === 'github')
      [providerId, username] = 'gi' + await githubProcessTokenPackage(code, state); //userText is the github id nr.
    else if (state.provider === data && data === 'google')
      [providerId, username] = await googleProcessTokenPackage(code); //the userText is the sub.
    else
      throw 'provider name is messed up';
    let uid = await KV_AUTH.get(providerId);
    if (!uid) {
      uid = (await count()).toString(36);
      await KV_AUTH.put(providerId, uid);
      await KV_AUTH.put('_' + uid, providerId);
    }
    const sessionObject = {
      iat: Date.now(),
      ttl: state.rememberMe ? SESSION_TTL : '',
      provider: state.provider,
      providerId,
      username
    };
    const sessionSecret = await encryptData(JSON.stringify(sessionObject), SECRET);
    delete sessionObject.providerId;
    return new Response(`<script>window.opener.postMessage('${JSON.stringify(sessionObject)}', 'https://${SESSION_ROOT}'); window.close();</script>`, {
      status: 200,
      headers: {
        'content-type': 'text/html',
        'Set-Cookie': bakeCookie(SESSION_COOKIE_NAME, sessionSecret, SESSION_ROOT, sessionObject.ttl)
      }
    });
  }
  if (action === 'logout') {
    return new Response(`<h3>You have logged out.</h3><script>setTimeout(()=>window.open('https://${SESSION_ROOT}'))</script>`, {
      status: 200,
      headers: {
        'content-type': 'text/html',
        'Set-Cookie': bakeCookie(SESSION_COOKIE_NAME, 'LoggingOut', SESSION_ROOT, 0)
      }
    });
  }
  return new Response('nothing to see', {status: 401});
}

addEventListener('fetch', e => e.respondWith(handleRequest(e.request)));