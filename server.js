// 云托管薄代理（过渡期版）
// 小程序 callContainer 调它：
//   /api/parse → 转发给 cn 解析，取回视频/图片的原始 CDN 直链
//   /api/save  → 直接从 CDN 拉媒体 → 传微信云存储 → 返回 fileID（小程序 downloadFile 存相册）
//   /api/clean → 删云存储临时文件
// 备案域名下来后，小程序改直连 cn，这个服务整个删掉即可。
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 80); // 微信云托管默认容器端口 80
const CN_BASE = process.env.CN_BASE || 'https://qsy-tc.myhkserver88.shop:8443';
const WX_ENV = process.env.WX_ENV || ''; // 云托管环境 ID（云存储要用）
const WX_API_BASE = process.env.WX_API_BASE || 'http://api.weixin.qq.com';
// Plan B：配了 APPID/APPSECRET 就用 access_token 走公网 HTTPS 调 tcb 接口，
// 绕过云托管「云调用」SafeLink 白名单（就是那个死活配不通的 85107）。
// 没配则回退到云调用免 token 方式（需微信令牌白名单）。
const APPID = process.env.APPID || '';
const APPSECRET = process.env.APPSECRET || '';
const SECRET = process.env.SECRET;
if (!SECRET) {
  console.error('缺少环境变量 SECRET');
  process.exit(1);
}

const SIGN_TTL_MS = 30 * 60 * 1000;
const RATE_LIMIT = 30;
const MAX_SAVE_BYTES = 300 * 1024 * 1024;
const MOBILE_UA =
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1';

// ---- 限流（按 openid，回退 IP）----
const hits = new Map();
function rateLimited(key) {
  const now = Date.now();
  const list = (hits.get(key) || []).filter((t) => now - t < 60_000);
  if (list.length >= RATE_LIMIT) return true;
  list.push(now);
  hits.set(key, list);
  return false;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, list] of hits) {
    const kept = list.filter((t) => now - t < 60_000);
    if (kept.length) hits.set(k, kept);
    else hits.delete(k);
  }
}, 60_000).unref();

// ---- 签名 ----
function sign(u, exp) {
  return crypto.createHmac('sha256', SECRET).update(`${u}|${exp}`).digest('hex');
}
function makeSavePath(realUrl) {
  const u = Buffer.from(realUrl).toString('base64url');
  const exp = Date.now() + SIGN_TTL_MS;
  return `/api/save?u=${u}&exp=${exp}&sig=${sign(u, exp)}`;
}
function verifySigned(url, res) {
  const u = url.searchParams.get('u');
  const exp = Number(url.searchParams.get('exp'));
  const sig = url.searchParams.get('sig');
  if (!u || !exp || !sig) return jsonRes(res, 400, { code: 400, msg: '参数不全' }), null;
  if (Date.now() > exp) return jsonRes(res, 403, { code: 403, msg: '链接已过期，请重新解析' }), null;
  const expect = sign(u, exp);
  if (sig.length !== expect.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expect))) {
    return jsonRes(res, 403, { code: 403, msg: '签名无效' }), null;
  }
  return Buffer.from(u, 'base64url').toString();
}

function jsonRes(res, code, body) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(body));
}

function fetchJson(urlStr, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const mod = urlStr.startsWith('https') ? https : http;
    const req = mod.get(urlStr, { headers: { 'User-Agent': MOBILE_UA, ...extraHeaders }, timeout: 20000 }, (r) => {
      let data = '';
      r.on('data', (c) => (data += c));
      r.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error('cn 返回非 JSON'));
        }
      });
    });
    req.on('timeout', () => req.destroy(new Error('cn 超时')));
    req.on('error', reject);
  });
}

function fetchJsonPost(urlStr, bodyObj) {
  return new Promise((resolve, reject) => {
    const mod = urlStr.startsWith('https') ? https : http;
    const payload = Buffer.from(JSON.stringify(bodyObj));
    const req = mod.request(
      urlStr,
      { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': payload.length }, timeout: 20000 },
      (r) => {
        let data = '';
        r.on('data', (c) => (data += c));
        r.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            reject(new Error('微信接口返回非 JSON'));
          }
        });
      }
    );
    req.on('timeout', () => req.destroy(new Error('微信接口超时')));
    req.on('error', reject);
    req.end(payload);
  });
}

// —— 微信 access_token（Plan B，绕过云调用白名单）——
let tokenCache = { token: '', exp: 0 };
async function getAccessToken() {
  const now = Date.now();
  if (tokenCache.token && now < tokenCache.exp) return tokenCache.token;
  const r = await fetchJson(
    `https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=${APPID}&secret=${APPSECRET}`
  );
  if (!r.access_token) throw new Error('获取 access_token 失败：' + JSON.stringify(r).slice(0, 150));
  tokenCache = { token: r.access_token, exp: now + (r.expires_in - 300) * 1000 };
  return tokenCache.token;
}
// 调 tcb 接口：配了 APPSECRET 就用 access_token 公网直连（不需白名单）；否则回退云调用（需白名单）
async function tcbPost(apiPath, body) {
  if (APPSECRET) {
    const token = await getAccessToken();
    return fetchJsonPost(`https://api.weixin.qq.com${apiPath}?access_token=${token}`, body);
  }
  return fetchJsonPost(`${WX_API_BASE}${apiPath}`, body);
}

// 从 cn 的 /api/media?u=xxx 路径里还原出原始 CDN 直链
function decodeMediaU(mediaPath) {
  try {
    const u = new URL(mediaPath, 'http://x').searchParams.get('u');
    return u ? Buffer.from(u, 'base64url').toString() : '';
  } catch (e) {
    return '';
  }
}

// 下载媒体到临时文件（跟随重定向）
function downloadToTmp(realUrl, depth = 0) {
  return new Promise((resolve, reject) => {
    if (depth > 5) return reject(new Error('重定向次数过多'));
    const mod = realUrl.startsWith('https') ? https : http;
    const req = mod.get(realUrl, { headers: { 'User-Agent': MOBILE_UA }, timeout: 30000 }, (r) => {
      if (r.statusCode >= 300 && r.statusCode < 400 && r.headers.location) {
        r.resume();
        return resolve(downloadToTmp(new URL(r.headers.location, realUrl).href, depth + 1));
      }
      if (r.statusCode !== 200) {
        r.resume();
        return reject(new Error(`拉取媒体失败 HTTP ${r.statusCode}`));
      }
      const tmpPath = path.join(os.tmpdir(), `qsy_${crypto.randomBytes(8).toString('hex')}`);
      const out = fs.createWriteStream(tmpPath);
      let size = 0;
      r.on('data', (c) => {
        size += c.length;
        if (size > MAX_SAVE_BYTES) r.destroy(new Error('文件过大'));
      });
      r.on('error', (e) => { out.destroy(); fs.unlink(tmpPath, () => {}); reject(e); });
      out.on('error', (e) => { fs.unlink(tmpPath, () => {}); reject(e); });
      out.on('finish', () => resolve({ path: tmpPath, size }));
      r.pipe(out);
    });
    req.on('timeout', () => req.destroy(new Error('拉取媒体超时')));
    req.on('error', reject);
  });
}

// 按微信云存储协议 multipart 上传
function uploadToCos(uploadUrl, fields, filePath, size) {
  return new Promise((resolve, reject) => {
    const boundary = '----qsy' + crypto.randomBytes(8).toString('hex');
    const head = Buffer.from(
      Object.entries(fields)
        .map(([k, v]) => `--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`)
        .join('') +
        `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="blob"\r\nContent-Type: application/octet-stream\r\n\r\n`
    );
    const tail = Buffer.from(`\r\n--${boundary}--\r\n`);
    const mod = uploadUrl.startsWith('https') ? https : http;
    const req = mod.request(
      uploadUrl,
      {
        method: 'POST',
        headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}`, 'Content-Length': head.length + size + tail.length },
        timeout: 120000,
      },
      (r) => {
        let data = '';
        r.on('data', (c) => (data += c));
        r.on('end', () => {
          if (r.statusCode >= 200 && r.statusCode < 300) resolve();
          else reject(new Error(`云存储上传失败 HTTP ${r.statusCode}: ${data.slice(0, 200)}`));
        });
      }
    );
    req.on('timeout', () => req.destroy(new Error('云存储上传超时')));
    req.on('error', reject);
    req.write(head);
    const fileStream = fs.createReadStream(filePath);
    fileStream.on('error', (e) => req.destroy(e));
    fileStream.on('end', () => req.end(tail));
    fileStream.pipe(req, { end: false });
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress;
  const rlKey = req.headers['x-wx-openid'] || ip;

  if (url.pathname === '/api/parse') {
    const shareUrl = url.searchParams.get('url');
    if (!shareUrl) return jsonRes(res, 400, { code: 400, msg: '缺少 url 参数' });
    if (rateLimited(rlKey)) return jsonRes(res, 429, { code: 429, msg: '请求太频繁，请稍后再试' });
    try {
      // 转发 openid 给 cn，让 cn 按用户限流（否则代理这一个出口 IP 会被 cn 整体限死）
      const openid = req.headers['x-wx-openid'];
      const upstream = await fetchJson(
        `${CN_BASE}/api/parse?url=${encodeURIComponent(shareUrl)}`,
        openid ? { 'X-WX-OPENID': openid } : {}
      );
      if (upstream.code !== 200 || !upstream.data) {
        return jsonRes(res, 200, { code: 500, msg: upstream.msg || '解析失败' });
      }
      const d = upstream.data; // cn H5 契约：{ title, desc?, cover_url, author, video_path, images:[{path}] }
      const videoCdn = d.video_path ? decodeMediaU(d.video_path) : '';
      const data = {
        title: d.title || '',
        desc: d.desc || d.title || '', // cn 更新后才有 desc（小红书正文）
        cover_url: d.cover_url || '',
        author: d.author || '',
        video_url: videoCdn, // 原始直链，播放用（抖音视频真机一般可直连）
        save_path: videoCdn ? makeSavePath(videoCdn) : '',
        // 图片：真机 <image> 直连小红书原始直链会被 CDN 防盗链拦成黑屏（开发者工具环境宽容所以正常）。
        // 改走 cn 公网 /api/media 中转 —— cn 已签好名、拉取用移动 UA 且不带 Referer，能绕过防盗链，
        // 与 H5 图片同一条通道。前端 item.url 字段不变，只是值从直链换成中转链接，透明切换。
        images: (d.images || [])
          .filter((i) => i && i.path)
          .map((i) => ({ url: CN_BASE + i.path, save_path: makeSavePath(decodeMediaU(i.path)) })),
      };
      return jsonRes(res, 200, { code: 200, msg: 'ok', data });
    } catch (e) {
      console.error('parse error:', e.message);
      return jsonRes(res, 200, { code: 500, msg: '解析服务异常，请稍后重试' });
    }
  }

  if (url.pathname === '/api/save') {
    const realUrl = verifySigned(url, res);
    if (!realUrl) return;
    if (!WX_ENV) return jsonRes(res, 200, { code: 501, msg: '未配置 WX_ENV，云存储不可用' });
    if (rateLimited(rlKey)) return jsonRes(res, 429, { code: 429, msg: '请求太频繁，请稍后再试' });
    let tmp;
    try {
      tmp = await downloadToTmp(realUrl);
      const day = new Date().toISOString().slice(0, 10);
      const cloudPath = `qsy/${day}/${crypto.randomBytes(6).toString('hex')}`;
      const meta = await tcbPost('/tcb/uploadfile', { env: WX_ENV, path: cloudPath });
      if (meta.errcode !== 0 || !meta.url) {
        // 诊断：把请求地址 / 环境ID / 微信原始返回（含 errcode）打全，定位"URL不在白名单"等
        console.error('[uploadfile失败]', `${WX_API_BASE}/tcb/uploadfile`, 'WX_ENV=', WX_ENV, 'resp=', JSON.stringify(meta));
        throw new Error('获取上传链接失败：' + JSON.stringify(meta).slice(0, 200));
      }
      await uploadToCos(
        meta.url,
        { key: cloudPath, Signature: meta.authorization, 'x-cos-security-token': meta.token, 'x-cos-meta-fileid': meta.cos_file_id },
        tmp.path,
        tmp.size
      );
      return jsonRes(res, 200, { code: 200, msg: 'ok', data: { file_id: meta.file_id } });
    } catch (e) {
      console.error('save error:', e.message);
      return jsonRes(res, 200, { code: 500, msg: '转存失败：' + e.message });
    } finally {
      if (tmp) fs.unlink(tmp.path, () => {});
    }
  }

  if (url.pathname === '/api/clean') {
    const fileid = url.searchParams.get('fileid');
    if (WX_ENV && fileid) {
      tcbPost('/tcb/batchdeletefile', { env: WX_ENV, fileid_list: [fileid] }).catch(() => {});
    }
    return jsonRes(res, 200, { code: 200, msg: 'ok' });
  }

  if (url.pathname === '/healthz' || url.pathname === '/') return jsonRes(res, 200, { ok: true });

  return jsonRes(res, 404, { code: 404, msg: 'not found' });
});

server.listen(PORT, () => console.log(`relay listening on :${PORT}, cn=${CN_BASE}`));
