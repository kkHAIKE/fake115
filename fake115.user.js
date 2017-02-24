// ==UserScript==
// @name         fake 115Browser
// @namespace    http://github.com/kkHAIKE/fake115
// @version      1.3.2
// @description  伪装115浏览器
// @author       kkhaike
// @match        *://115.com/*
// @grant        GM_xmlhttpRequest
// @grant        unsafeWindow
// @grant        GM_log
// @connect      passport.115.com
// @connect      passportapi.115.com
// @connect      proapi.115.com
// @connect      uplb.115.com
// @require      http://cdn.bootcss.com/crc-32/0.4.1/crc32.min.js
// @require      http://cdn.bootcss.com/blueimp-md5/2.3.0/js/md5.min.js
// @require      https://rawgit.com/ricmoo/aes-js/master/index.js
// @require      https://rawgit.com/kkHAIKE/node-lz4/balabala/build/lz4.min.js
// @require      https://rawgit.com/indutny/elliptic/master/dist/elliptic.min.js
// @require      https://rawgit.com/emn178/js-md4/master/build/md4.min.js
// @require      https://rawgit.com/kkHAIKE/fake115/master/fec115.min.js
// @require      http://cdn.bootcss.com/jsSHA/2.2.0/sha1.js
// @run-at       document-start
// ==/UserScript==
(function() {
    'use strict';
var Buffer, LZ4, LoginEncrypt_, browserInterface, bytesToHex, bytesToString, dictToForm, dictToQuery, ec115_compress_decode, ec115_decode, ec115_decode_aes, ec115_encode_data, ec115_encode_token, ec115_init, g_ver, get_key, md4_init, preLoginEncrypt, ref, sig_calc, sig_init, stringToBytes;

g_ver = '8.0.0.52';

Buffer = require('buffer').Buffer;

LZ4 = require('lz4');

stringToBytes = function(s) {
  var i, l, ref, ret;
  ret = [];
  for (i = l = 0, ref = s.length; 0 <= ref ? l < ref : l > ref; i = 0 <= ref ? ++l : --l) {
    ret.push(s.charCodeAt(i));
  }
  return ret;
};

bytesToString = function(b) {
  var i, l, len1, ret;
  ret = '';
  for (l = 0, len1 = b.length; l < len1; l++) {
    i = b[l];
    ret += String.fromCharCode(i);
  }
  return ret;
};

bytesToHex = function(b) {
  var l, len1, ret, t;
  ret = '';
  for (l = 0, len1 = b.length; l < len1; l++) {
    t = b[l];
    ret += (t >> 4).toString(16);
    ret += (t & 0xf).toString(16);
  }
  return ret;
};

ec115_init = function() {
  var Q, c, key, keys, pub;
  c = new elliptic.ec('p224');
  keys = c.genKeyPair();
  pub = [0x1d].concat(keys.getPublic(true, true));
  Q = c.keyFromPublic('0457A29257CD2320E5D6D143322FA4BB8A3CF9D3CC623EF5EDAC62B7678A89C91A83BA800D6129F522D034C895DD2465243ADDC250953BEEBA'.toLowerCase(), 'hex');
  key = (keys.derive(Q.getPublic())).toArray();
  return {
    pub: pub,
    key: key
  };
};

ec115_encode_token = function(pub, tm, cnt) {
  var i, l, m, o, q, r20, r21, tmp, tmp2;
  r20 = Math.floor(Math.random() * 256);
  r21 = Math.floor(Math.random() * 256);
  tmp = Buffer.alloc(48);
  for (i = l = 0; l < 15; i = ++l) {
    tmp[i] = pub[i] ^ r20;
  }
  tmp[15] = r20;
  tmp.writeInt32LE(115, 16);
  tmp.writeInt32LE(tm, 20);
  for (i = m = 16; m < 24; i = ++m) {
    tmp[i] ^= r20;
  }
  for (i = o = 24; o < 39; i = ++o) {
    tmp[i] = pub[i - 9] ^ r21;
  }
  tmp[39] = r21;
  tmp.writeInt32LE(cnt, 40);
  for (i = q = 40; q < 44; i = ++q) {
    tmp[i] ^= r21;
  }
  tmp2 = Buffer.concat([Buffer.from('^j>WD3Kr?J2gLFjD4W2y@'), tmp.slice(0, 44)]);
  tmp.writeInt32LE(CRC32.buf(tmp2), 44);
  return tmp.toString('base64');
};

ec115_encode_data = function(data, key) {
  var aesEcb, i, j, k, key1, key2, l, n, part, rets, tmp;
  key1 = key.slice(0, 16);
  key2 = key.slice(-16);
  aesEcb = new aesjs.ModeOfOperation.ecb(key1);
  tmp = stringToBytes(data);
  n = tmp.length;
  j = 0;
  rets = [];
  while (n > 0) {
    part = Buffer.alloc(16);
    for (i = l = 0; l < 16; i = ++l) {
      k = n <= 0 ? 0 : tmp[i + j];
      part[i] = key2[i] ^ k;
      --n;
    }
    key2 = aesEcb.encrypt(part);
    rets.push(Buffer.from(key2));
    j += 16;
  }
  return Buffer.concat(rets).toString('latin1');
};

ec115_decode_aes = function(data, key) {
  var aesCbc, i, iv, key1, ret;
  key1 = key.slice(0, 16);
  iv = key.slice(-16);
  aesCbc = new aesjs.ModeOfOperation.cbc(key1, iv);
  ret = aesCbc.decrypt(data);
  i = ret.length;
  while (i > 0 && ret[i - 1] === 0) {
    --i;
  }
  return Buffer.from(ret.buffer, ret.byteOffset, i);
};

ec115_compress_decode = function(data) {
  var len, p, r, rets, tmp;
  p = 0;
  rets = [];
  while (p < data.length) {
    len = data.readInt16LE(p) + 2;
    if (p + len > data.length) {
      return null;
    }
    tmp = Buffer.alloc(0x2000);
    r = LZ4.decodeBlock(data.slice(p + 2, p + len), tmp);
    if (r < 0) {
      return null;
    }
    rets.push(tmp.slice(0, r));
    p += len;
  }
  return Buffer.concat(rets);
};

get_key = function(data_buf) {
  var i, l, p, ret, t;
  p = 0;
  ret = Buffer.alloc(40);
  for (i = l = 0; l < 40; i = ++l) {
    t = data_buf.readInt32LE(p);
    p = t + 1;
    ret[i] = data_buf[t];
  }
  return ret;
};

md4_init = function(pSig) {
  var ret;
  ret = md4.create();
  ret.h0 = pSig.readInt32LE(4);
  ret.h1 = pSig.readInt32LE(8);
  ret.h2 = pSig.readInt32LE(12);
  ret.h3 = pSig.readInt32LE(16);
  ret.first = false;
  return ret;
};

sig_init = function(body) {
  var data_buf, data_buf_p, dhash, md4h, ori_data_p, pSig, sz;
  ori_data_p = Module._malloc(body.length);
  Module.HEAPU8.set(body, ori_data_p);
  data_buf_p = Module._malloc(body.length);
  sz = Module.ccall('calc_out', 'number', ['number', 'number', 'number'], [ori_data_p, body.length, data_buf_p]);
  Module._free(ori_data_p);
  data_buf = Buffer.from(Module.buffer, data_buf_p, sz);
  pSig = get_key(data_buf);
  md4h = md4_init(pSig);
  md4h.update(data_buf);
  dhash = md4h.digest();
  return {
    data_buf: data_buf,
    data_buf_p: data_buf_p,
    pSig: pSig,
    dhash: dhash
  };
};

sig_calc = function(arg, src) {
  var data_buf, data_buf_p, dhash, h1, h1_p, i, l, md4h, out_data, out_data_p, pSig, ret, sz;
  data_buf = arg.data_buf, data_buf_p = arg.data_buf_p, pSig = arg.pSig, dhash = arg.dhash;
  md4h = md4_init(pSig);
  md4h.update(dhash);
  md4h.update(src);
  md4h.update(pSig);
  h1 = new Uint8Array(md4h.buffer());
  h1_p = Module._malloc(16);
  Module.HEAPU8.set(h1, h1_p);
  out_data_p = Module._malloc(0x10000);
  sz = Module.ccall('encode', 'number', ['number', 'number', 'number', 'number', 'number', 'number', 'number'], [data_buf_p, data_buf.length / 2, h1_p, 16, out_data_p, 8, 10]);
  Module._free(data_buf_p);
  Module._free(h1_p);
  out_data = new Uint8Array(Module.buffer, out_data_p, sz);
  md4h = md4_init(pSig);
  md4h.update(out_data);
  ret = md4h.digest();
  Module._free(out_data_p);
  ret.push(pSig[0]);
  for (i = l = 36; l < 40; i = ++l) {
    ret.push(pSig[i]);
  }
  return bytesToHex(ret);
};

ec115_decode = function(data, key) {
  var dec, unzip;
  dec = data[data.length - 12 + 5];
  unzip = data[data.length - 12 + 4];
  data = data.slice(0, -12);
  if (dec === 1) {
    data = ec115_decode_aes(data, key);
  }
  if ((data != null) && unzip === 1) {
    data = ec115_compress_decode(data);
  }
  return data;
};

dictToQuery = function(dict) {
  var k, tmp, v;
  tmp = [];
  for (k in dict) {
    v = dict[k];
    tmp.push((encodeURIComponent(k)) + "=" + (encodeURIComponent(v)));
  }
  return tmp.join('&');
};

dictToForm = function(dict) {
  var k, tmp, v;
  tmp = [];
  for (k in dict) {
    v = dict[k];
    tmp.push(k + "=" + v);
  }
  return tmp.join('&');
};

LoginEncrypt_ = function(arg, g, arg1, sig) {
  var account, data, environment, fake, goto, key, login_type, passwd, pub, tm, tmus, token;
  account = arg.account, passwd = arg.passwd, environment = arg.environment, goto = arg.goto, login_type = arg.login_type;
  pub = arg1.pub, key = arg1.key;
  tmus = (new Date()).getTime();
  tm = Math.floor(tmus / 1000);
  fake = md5(account);
  token = ec115_encode_token(pub, tm, 1);
  data = ec115_encode_data(dictToForm({
    GUID: fake.slice(0, 20),
    account: account,
    device: 'DEEPIN',
    device_id: fake.slice(1, 13).toUpperCase(),
    device_type: 'windows',
    disk_serial: fake.slice(0, 8).toUpperCase(),
    dk: '',
    environment: environment,
    goto: goto,
    login_source: '115chrome',
    network: '5',
    passwd: passwd,
    sign: md5("" + account + tm),
    system_info: ("            " + fake[1] + fake[0] + fake[3] + fake[2] + fake[5] + fake[4] + fake[7] + fake[6]).toUpperCase(),
    time: tm,
    login_type: login_type,
    sign115: sig_calc(sig, md5("" + account + tm))
  }), key);
  return GM_xmlhttpRequest({
    method: 'POST',
    url: "http://passport.115.com/?ct=encrypt&ac=login&k_ec=" + token,
    data: data,
    binary: true,
    responseType: 'arraybuffer',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
    },
    onload: function(response) {
      var date, datestr, json;
      if (response.status === 200) {
        data = Buffer.from(response.response);
        data = ec115_decode(data, key);
        if (data != null) {
          json = JSON.parse(data.toString('latin1'));
          if (json.state && (json.data != null)) {
            date = new Date();
            date.setTime(date.getTime() + 7 * 24 * 3600 * 1000);
            datestr = date.toGMTString();
            document.cookie = "UID=" + json.data.cookie.UID + "; expires=" + datestr + "; path=/; domain=115.com";
            document.cookie = "CID=" + json.data.cookie.CID + "; expires=" + datestr + "; path=/; domain=115.com";
            document.cookie = "SEID=" + json.data.cookie.SEID + "; expires=" + datestr + "; path=/; domain=115.com";
            document.cookie = "OOFL=" + json.data.user_id + "; expires=" + datestr + "; path=/; domain=115.com";
            delete json.data;
          }
          return unsafeWindow[g](JSON.stringify(json));
        } else {
          return GM_log('data is null');
        }
      } else {
        return GM_log("response.status = " + response.status);
      }
    }
  });
};

preLoginEncrypt = function(n, g) {
  var key, pub, ref, tm, tmus, token;
  tmus = (new Date()).getTime();
  tm = Math.floor(tmus / 1000);
  ref = ec115_init(), pub = ref.pub, key = ref.key;
  token = ec115_encode_token(pub, tm, 0);
  return GM_xmlhttpRequest({
    method: 'GET',
    url: "https://passportapi.115.com/app/2.0/web/" + g_ver + "/login/sign?k_ec=" + token,
    responseType: 'arraybuffer',
    anonymous: true,
    onload: function(response) {
      var body, data, error, json, sig;
      if (response.status === 200) {
        data = Buffer.from(response.response);
        data = ec115_decode(data, key);
        if (data != null) {
          json = JSON.parse(data.toString('latin1'));
          if (json.state) {
            body = Buffer.from(json.sign, 'base64');
            try {
              sig = sig_init(body);
              return LoginEncrypt_(JSON.parse(n), g, {
                pub: pub,
                key: key
              }, sig);
            } catch (error1) {
              error = error1;
              return GM_log("" + error.stack);
            }
          } else {
            return GM_log(JSON.stringify(json));
          }
        } else {
          return GM_log('data is null');
        }
      } else {
        return GM_log("response.status = " + response.status);
      }
    }
  });
};

browserInterface = (ref = unsafeWindow.browserInterface) != null ? ref : {};

browserInterface.LoginEncrypt = function(n, g) {
  var error;
  try {
    return preLoginEncrypt(n, g);
  } catch (error1) {
    error = error1;
    return GM_log("" + error.stack);
  }
};

unsafeWindow.browserInterface = cloneInto(browserInterface, unsafeWindow, {
  cloneFunctions: true
});

unsafeWindow.document.addEventListener('DOMContentLoaded', function() {
  var cont, error, fakeSizeLimitGetter, fastSig, fastUpload, finput, getUserKey, js_top_panel_box, procLabel, uploadinfo;
  try {
    js_top_panel_box = unsafeWindow.document.getElementById('js_top_panel_box');
    if (js_top_panel_box != null) {
      cont = document.createElement('div');
      finput = document.createElement('input');
      finput.setAttribute('type', 'file');
      procLabel = document.createElement('span');
      cont.appendChild(finput);
      cont.appendChild(procLabel);
      js_top_panel_box.appendChild(cont);
      cont.style.position = 'absolute';
      cont.style.top = '20px';
      cont.style.left = '80px';
      fastSig = function(userid, fileid, target, userkey) {
        var sha1, tmp;
        sha1 = new jsSHA('SHA-1', 'TEXT');
        sha1.update("" + userid + fileid + target + "0");
        tmp = sha1.getHash('HEX');
        sha1 = new jsSHA('SHA-1', 'TEXT');
        sha1.update("" + userkey + tmp + "000000");
        return sha1.getHash('HEX', {
          outputUpper: true
        });
      };
      uploadinfo = null;
      fastUpload = function(arg) {
        var fileid, filename, filesize, preid, tm, tmus;
        fileid = arg.fileid, preid = arg.preid, filename = arg.filename, filesize = arg.filesize;
        tmus = (new Date()).getTime();
        tm = Math.floor(tmus / 1000);
        return GM_xmlhttpRequest({
          method: 'POST',
          url: uploadinfo.url_upload + '?' + dictToQuery({
            appid: 0,
            appfrom: 10,
            appversion: '2.0.0.0',
            format: 'json',
            isp: 0,
            sig: fastSig(uploadinfo.user_id, fileid, 'U_1_0', uploadinfo.userkey),
            t: tm
          }),
          data: dictToForm({
            api_version: '2.0.0.0',
            fileid: fileid,
            filename: filename,
            filesize: filesize,
            preid: preid,
            target: 'U_1_0',
            userid: uploadinfo.user_id
          }),
          responseType: 'json',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
          },
          onload: function(response) {
            if (response.status === 200) {
              if (response.response.status === 2) {
                return alert('fastupload OK, refresh window and goto root folder to find it');
              } else {
                return alert('fastupload FAIL, LOL');
              }
            } else {
              return GM_log("response.status = " + response.status);
            }
          }
        });
      };
      getUserKey = function(param) {
        return GM_xmlhttpRequest({
          method: 'GET',
          url: 'http://proapi.115.com/app/uploadinfo',
          responseType: 'json',
          onload: function(response) {
            if (response.status === 200) {
              uploadinfo = response.response;
              return fastUpload(param);
            } else {
              return GM_log("response.status = " + response.status);
            }
          }
        });
      };
      finput.onchange = function(e) {
        var PSIZE, allSha1, f, finalPart, nextPart, npart, preid;
        if (e.target.files.length === 0) {
          return;
        }
        f = e.target.files[0];
        if (f.size < 128 * 1024) {
          alert('file size less than 128K');
          return;
        }
        PSIZE = 1 * 1024 * 1024;
        npart = Math.floor((f.size + PSIZE - 1) / PSIZE);
        allSha1 = new jsSHA('SHA-1', 'ARRAYBUFFER');
        preid = '';
        finalPart = function() {
          var fileid, param;
          fileid = allSha1.getHash('HEX', {
            outputUpper: true
          });
          param = {
            fileid: fileid,
            preid: preid,
            filename: f.name,
            filesize: f.size
          };
          if (uploadinfo != null) {
            return fastUpload(param);
          } else {
            return getUserKey(param);
          }
        };
        nextPart = function(n) {
          var b, reader;
          reader = new FileReader();
          b = f.slice(n * PSIZE, (n + 1) * PSIZE > f.size ? f.size : (n + 1) * PSIZE);
          reader.onerror = function(e) {
            return GM_log("" + e.target.error);
          };
          reader.onload = function(e) {
            var data, sha1;
            data = new Uint8Array(e.target.result);
            if (n === 0) {
              sha1 = new jsSHA('SHA-1', 'ARRAYBUFFER');
              sha1.update(data.slice(0, 128 * 1024));
              preid = sha1.getHash('HEX', {
                outputUpper: true
              });
            }
            allSha1.update(data);
            procLabel.textContent = "(" + (Math.floor((n + 1) * 100 / npart)) + "%)";
            if (n === npart - 1) {
              return finalPart();
            } else {
              return nextPart(n + 1);
            }
          };
          return reader.readAsArrayBuffer(b);
        };
        return nextPart(0);
      };
    }
    if (unsafeWindow.UPLOAD_CONFIG_H5 != null) {
      fakeSizeLimitGetter = function() {
        return 115 * 1024 * 1024 * 1024;
      };
      if (Object.defineProperty != null) {
        return Object.defineProperty(unsafeWindow.UPLOAD_CONFIG_H5, 'size_limit', {
          get: fakeSizeLimitGetter
        });
      } else if (Object.prototype.__defineGetter__ != null) {
        return unsafeWindow.UPLOAD_CONFIG_H5.__defineGetter__('size_limit', fakeSizeLimitGetter);
      }
    }
  } catch (error1) {
    error = error1;
    return GM_log("" + error.stack);
  }
});

})();
