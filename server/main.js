//ROOT (directory. DO NOT END WITH '/'!!)
function mimeType(path){
  const filetype = path.substr(path.lastIndexOf('.')+1);
  return {
    'html': 'text/html',
    'js': 'text/javascript',
    'css': 'text/css'
  }[filetype];
}

async function handleRequest(req) {
  const url = new URL(req.url);
  let path = url.pathname;
  if (path === '' || path === '/')
    path = '/index.html';
  const headers = {'content-type': mimeType(path)};
  const rawgit = await fetch(ROOT + path, {cf: {cacheTtl: -1}});//do not cache
  if(rawgit.status === 200)
    return new Response(await rawgit.text(), {status: 200, headers});
  return rawgit;
}

addEventListener('fetch', e => e.respondWith(handleRequest(e.request)));