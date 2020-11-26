
//SESSION_COOKIE_NAME
//SECRET
//KV_MAIN

//pure functions
function getCookieValue(cookie, key) {
  return cookie?.match(`(^|;)\\s*${key}\\s*=\\s*([^;]+)`)?.pop();
}

function hexStringToUint8(str) {
  return new Uint8Array(str.match(/.{2}/g).map(byte => parseInt(byte, 16)));
}

function fromBase64url(base64urlStr) {
  base64urlStr = base64urlStr.replace(/-/g, '+').replace(/_/g, '/');
  if (base64urlStr.length % 4 === 2)
    return base64urlStr + '==';
  if (base64urlStr.length % 4 === 3)
    return base64urlStr + '=';
  return base64urlStr;
}

let cachedPassHash;

async function passHash(pw) {
  return cachedPassHash || (cachedPassHash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pw)));
}

async function makeKeyAESGCM(password, iv) {
  const pwHash = await passHash(password);
  const alg = {name: 'AES-GCM', iv: iv};                            // specify algorithm to use
  return await crypto.subtle.importKey('raw', pwHash, alg, false, ['decrypt', 'encrypt']);  // use pw to generate key
}

async function decryptAESGCM(password, iv, ctStr) {
  const key = await makeKeyAESGCM(password, iv);
  const ctUint8 = new Uint8Array(ctStr.match(/[\s\S]/g).map(ch => ch.charCodeAt(0))); // ciphertext as Uint8Array
  const plainBuffer = await crypto.subtle.decrypt({name: key.algorithm.name, iv: iv}, key, ctUint8);                 // decrypt ciphertext using key
  return new TextDecoder().decode(plainBuffer);                                       // return the plaintext
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
// pure functions end

const GET = {
  ALL: async function ALL() {
    return await KV_MAIN.list();
  },
  FILES: async function FILES(uid) {
    const {keys} = await KV_MAIN.list({prefix: `${uid}/`});
    const res = new Set();
    for (let {name} of keys)
      res.add(name.split('/')[1]);
    return Array.from(res);
  },
  FILE: async function FILE(uid, filename) {
    const {keys} = await KV_MAIN.list({prefix: `${uid}/${filename}`});
    const res = {};
    for (let {name, metadata} of keys)
      res[name] = metadata ? JSON.stringify(metadata) : await KV_MAIN.get(name);
    return res;
  }
}

const POST_AUTH = {
  WRITE: async function WRITE(entryArray, sessionObj, user, filename) {
    const newTime = Date.now();
    for (let {op, point2, data} of entryArray) {
      const dataJson = JSON.stringify(data);
      const newKey = [user, filename, newTime, op, point2].join('/');
      new TextEncoder().encode(dataJson).length < 1024 ?
        await KV_MAIN.put(newKey, null, {metadata: data}) :
        await KV_MAIN.put(newKey, dataJson);
      res.push(newKey);
    }
    return res;
  }
}

const GET_AUTH = {
  SESSION: async function SESSION(sessionObj){
    return sessionObj;
  }
}

async function decryptSession(cookie) {
  return JSON.parse(await decryptData(cookie, SECRET));
}


/**
 * GET  /SESSION
 * GET  /ALL
 * GET  /FILES/uid
 * GET  /FILE/uid/filename
 * POST /WRITE/uid/filename
 *      JSON =
 [
   {"op": "op1", "point2": "it/test.html/160000000", "data": "some data"},
   {"op": "op2", "point2": "it/test.html/160000000", "data": "hello"},
   {"op": "op1", "point2": "it/test.html/159191919", "data": "simi diti"}
 ]
 */
async function handleRequest(req) {
  try{

  const url = new URL(req.url);
  const [ignore, action, wantedUID, filename] = url.pathname.split('/');
  const getAction = GET[action];
  if (getAction)
    return new Response(JSON.stringify(getAction(wantedUID, filename)), {status: 200});

  const sessionObj = await decryptSession(getCookieValue(req.headers.get('cookie'), SESSION_COOKIE_NAME), wantedUID);

  const getAuthAction = GET_AUTH[action];
  if (getAuthAction)
    return new Response(JSON.stringify(getAuthAction(sessionObj)), {status: 200});

  const postAction = POST_AUTH[action] ;
  if (!postAction)
    return new Response('Unknown action: ' + action, {status: 401});

  if (sessionObj.uid !== wantedUID)
    return new Response('Invalid uid: ' + wantedUID, {status: 401});

  return new Response(JSON.stringify(postAction(await req.json(), sessionObj, wantedUID, filename)), {status: 200});
  }catch(err){
    return new Response(err.message, {status: 401});
  }
}

addEventListener('fetch', e => e.respondWith(handleRequest(e.request)));