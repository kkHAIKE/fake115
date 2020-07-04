`// ==UserScript==
// @name         fake 115Browser
// @namespace    http://github.com/kkHAIKE/fake115
// @version      1.3.8
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
// @require      https://cdn.bootcss.com/crc-32/1.2.0/crc32.min.js
// @require      https://cdn.bootcss.com/blueimp-md5/2.10.0/js/md5.min.js
// @require      https://cdn.bootcss.com/aes-js/3.1.0/index.min.js
// @require      https://raw.github.com/kkHAIKE/node-lz4/balabala/build/lz4.min.js
// @require      https://raw.github.com/indutny/elliptic/master/dist/elliptic.min.js
// @require      https://raw.github.com/emn178/js-md4/master/build/md4.min.js
// @require      https://raw.github.com/kkHAIKE/fake115/master/fec115.min.js
// @require      https://cdn.bootcss.com/jsSHA/2.3.1/sha1.js
// @require      https://raw.github.com/pierrec/js-xxhash/master/build/xxhash.min.js
// @require      https://raw.github.com/omichelsen/compare-versions/master/index.js
// @run-at       document-start
// ==/UserScript==
(function() {
    'use strict'`
g_ver = '8.3.0.25'

Buffer = require('buffer').Buffer
LZ4 = require 'lz4'
elliptic = window.elliptic
md4 = window.md4

stringToBytes = (s) ->
  ret = []
  for i in [0...s.length]
    ret.push s.charCodeAt i
  return ret

bytesToString = (b) ->
  ret = ''
  for i in b
    ret += String.fromCharCode i
  return ret

bytesToHex = (b) ->
  ret = ''
  for t in b
    ret += (t >> 4).toString 16
    ret += (t & 0xf).toString 16
  return ret

ec115_init = ->
  c = new elliptic.ec 'p224'
  keys = c.genKeyPair()
  pub = [0x1d].concat keys.getPublic true, true
  Q = c.keyFromPublic '0457A29257CD2320E5D6D143322FA4BB8A3CF9D3CC623EF5EDAC62B7678A89C91A83BA800D6129F522D034C895DD2465243ADDC250953BEEBA'.toLowerCase(), 'hex'
  key = (keys.derive Q.getPublic()).toArray()
  return {pub, key}

ec115_encode_token = (pub, tm, cnt) ->
  r20 = Math.floor Math.random() * 256;
  r21 = Math.floor Math.random() * 256;

  tmp = Buffer.alloc 48
  for i in [0...15]
    tmp[i] = pub[i] ^ r20
  tmp[15] = r20
  tmp.writeInt32LE 115, 16
  tmp.writeInt32LE tm, 20
  for i in [16...24]
    tmp[i] ^= r20
  for i in [24...39]
    tmp[i] = pub[i - 9] ^ r21
  tmp[39] = r21
  tmp.writeInt32LE cnt, 40
  for i in [40...44]
    tmp[i] ^= r21

  tmp2 = Buffer.concat [Buffer.from('^j>WD3Kr?J2gLFjD4W2y@'), tmp[0...44]]
  tmp.writeInt32LE CRC32.buf(tmp2), 44

  return tmp.toString 'base64'

ec115_encode_data = (data, key) ->
  key1 = key[0...16]
  key2 = key[-16...]
  aesEcb = new aesjs.ModeOfOperation.ecb key1
  tmp = stringToBytes data

  n = tmp.length
  j = 0
  rets = []
  while n > 0
    part = Buffer.alloc 16
    for i in [0...16]
      k = if n <= 0 then 0 else tmp[i + j]
      part[i] = key2[i] ^ k
      --n

    key2 = aesEcb.encrypt part
    rets.push Buffer.from key2

    j += 16
  return Buffer.concat rets


ec115_decode_aes = (data, key) ->
  key1 = key[0...16]
  iv = key[-16...]

  aesCbc = new aesjs.ModeOfOperation.cbc key1, iv
  ret = aesCbc.decrypt data

  i = ret.length
  while i > 0 and ret[i - 1] is 0
    --i
  return Buffer.from ret.buffer, ret.byteOffset, i

ec115_compress_decode = (data) ->
  p = 0
  rets = []
  while p < data.length
    len = data.readInt16LE(p) + 2
    return null if p + len > data.length

    tmp = Buffer.alloc 0x2000
    r = LZ4.decodeBlock data[p + 2...p + len], tmp
    return null if r < 0

    rets.push tmp[0...r]
    p += len
  return Buffer.concat rets

get_key = (data_buf) ->
  p = 0
  ret = Buffer.alloc 40
  for i in [0...40]
    t = data_buf.readInt32LE p
    p = t + 1
    ret[i] = data_buf[t]
  return ret

md4_init = (pSig) ->
  ret = md4.create()
  ret.h0 = pSig.readInt32LE 4
  ret.h1 = pSig.readInt32LE 8
  ret.h2 = pSig.readInt32LE 12
  ret.h3 = pSig.readInt32LE 16
  ret.first = false
  return ret

sig_init = (body) ->
  ori_data_p = Module._malloc body.length
  Module.HEAPU8.set body, ori_data_p
  data_buf_p = Module._malloc body.length
  sz = Module.ccall 'calc_out', 'number', ['number', 'number', 'number'],
    [ori_data_p, body.length, data_buf_p]
  Module._free ori_data_p
  data_buf = Buffer.from Module.buffer, data_buf_p, sz
  pSig = get_key data_buf

  md4h = md4_init pSig
  md4h.update data_buf
  dhash = md4h.digest()
  return {data_buf, data_buf_p, pSig, dhash}

sig_calc = ({data_buf, data_buf_p, pSig, dhash}, src) ->
  xxh = XXH.h64()
  xxh.init pSig.readUInt32LE 8
  xxh.update src
  h2 = xxh.digest().toString(16)
  pad = '0000000000000000'
  h2b = Buffer.from(pad[0...16 - h2.length] + h2, 'hex').swap64()

  md4h = md4_init pSig
  md4h.update dhash
  md4h.update src
  md4h.update h2b
  md4h.update pSig
  h1 = new Uint8Array md4h.buffer()

  h1_p = Module._malloc 16
  Module.HEAPU8.set h1, h1_p
  out_data_p = Module._malloc 0x10000
  sz = Module.ccall 'encode', 'number',
    ['number', 'number', 'number', 'number', 'number', 'number', 'number'],
    [data_buf_p, data_buf.length / 2, h1_p, 16, out_data_p, 8, 10]
  Module._free data_buf_p
  Module._free h1_p

  out_data = new Uint8Array Module.buffer, out_data_p, sz
  md4h = md4_init pSig
  md4h.update out_data
  ret = md4h.digest()
  Module._free out_data_p

  ret.push pSig[0]
  for i in [36...40]
    ret.push pSig[i]
  return bytesToHex ret

ec115_decode = (data, key) ->
  dec = data[data.length - 12 + 5]
  unzip = data[data.length - 12 + 4]
  data = data[0...-12]

  if dec is 1
    data = ec115_decode_aes data, key
  if data? and unzip is 1
    data = ec115_compress_decode data
  return data

dictToQuery = (dict) ->
  tmp = []
  for k, v of dict
    tmp.push "#{encodeURIComponent(k)}=#{encodeURIComponent(v)}"
  return tmp.join '&'

dictToForm = (dict) ->
  tmp = []
  for k, v of dict
    tmp.push "#{k}=#{v}"
  return tmp.join '&'

LoginEncrypt_ = ({account, passwd, environment, goto, login_type}, g, {pub, key}, sig) ->
  tmus = (new Date()).getTime()
  tm = tmus // 1000
  fake = md5 account

  token = ec115_encode_token pub, tm, 1

  data = ec115_encode_data dictToForm(
    GUID: fake[0...20]
    account: account
    device: 'GhostXP' # hostname
    device_id: fake[2...14].toUpperCase() # mac
    device_type: 'windows'
    disk_serial: fake[0...8].toUpperCase() # harddisk serial
    dk: ''
    environment: environment
    goto: goto
    login_source: '115chrome'
    network: '5'
    passwd: passwd
    sign: md5 "#{account}#{tm}"
    system_info: "            #{fake[1]}#{fake[0]}#{fake[3]}#{fake[2]}#{fake[5]}#{fake[4]}#{fake[7]}#{fake[6]}".toUpperCase()
    # sha1(user sid (unicode)) + c volume serial + checksum
    time: tm
    login_type: login_type
    signew: 1
    sign115: sig_calc sig, md5 "#{account}#{tm}"
    ), key

  GM_xmlhttpRequest
    method: 'POST'
    url: "http://passport.115.com/?ct=encrypt&ac=login&k_ec=#{token}" #encodeURIComponent
    data: if GM_info.scriptHandler is 'Violentmonkey' and compareVersions.compare GM_info.version, 'v2.12.2', '<' then new Blob [data.buffer], {type: 'application/octet-binary'} else data.toString 'latin1'
    binary: true
    responseType: 'arraybuffer'
    #overrideMimeType: 'text\/plain; charset=x-user-defined'
    headers:
      'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
    #anonymous: true
    onerror: (response)->
      GM_log "response.status = #{response.status}, response.statusText = #{response.statusText}"
    onload: (response)->
      if response.status is 200
        data = Buffer.from response.response
        data = ec115_decode data, key

        if data?
          json = JSON.parse data.toString 'latin1'
          if json.state and json.data?
            date = new Date()
            date.setTime date.getTime() + 7 * 24 * 3600 * 1000
            datestr = date.toGMTString()

            document.cookie = "UID=#{json.data.cookie.UID}; expires=#{datestr}; path=/; domain=115.com"
            document.cookie = "CID=#{json.data.cookie.CID}; expires=#{datestr}; path=/; domain=115.com"
            document.cookie = "SEID=#{json.data.cookie.SEID}; expires=#{datestr}; path=/; domain=115.com"
            document.cookie = "OOFL=#{json.data.user_id}; expires=#{datestr}; path=/; domain=115.com"

            #json.goto = "#{json.goto}#{encodeURIComponent(goto)}"
            delete json.data
          unsafeWindow[g] JSON.stringify json
        else
          GM_log 'data is null'
      else
        GM_log "response.status = #{response.status}"

preLoginEncrypt = (n,g) ->
  tmus = (new Date()).getTime()
  tm = tmus // 1000
  {pub, key} = ec115_init()
  token = ec115_encode_token pub, tm, 0

  GM_xmlhttpRequest
    method: 'GET'
    url: "https://passportapi.115.com/app/2.0/web/#{g_ver}/login/sign?k_ec=#{token}"
    responseType: 'arraybuffer'
    anonymous: true
    onerror: (response)->
      GM_log "response.status = #{response.status}, response.statusText = #{response.statusText}"
    onload: (response)->
      if response.status is 200
        data = Buffer.from response.response
        data = ec115_decode data, key

        if data?
          json = JSON.parse data.toString 'latin1'
          if json.state
            body = Buffer.from json.sign, 'base64'

            try
              sig = sig_init body

              LoginEncrypt_ JSON.parse(n), g, {pub, key}, sig
            catch error
              GM_log "#{error.message}\n#{error.stack}"
          else
            GM_log JSON.stringify json
        else
          GM_log 'data is null'
      else
        GM_log "response.status = #{response.status}"

browserInterface = unsafeWindow.browserInterface ? {}
browserInterface.LoginEncrypt = (n,g) ->
  try
    preLoginEncrypt n, g
  catch error
    GM_log "#{error.message}\n#{error.stack}"

browserInterface.GetBrowserVersion = ->
  new String(g_ver)

browserInterface.ChromeGetIncognitoState = ->
  false

if typeof cloneInto isnt 'function'
  cloneInto = (x) -> x

unsafeWindow.browserInterface = cloneInto browserInterface, unsafeWindow, {cloneFunctions: true}

unsafeWindow.document.addEventListener 'DOMContentLoaded', ->
  try
    js_top_panel_box = unsafeWindow.document.getElementById 'js_top_panel_box'
    if js_top_panel_box?
      cont = document.createElement 'div'
      finput = document.createElement 'input'
      finput.setAttribute 'type', 'file'
      procLabel = document.createElement 'span'
      cont.appendChild finput
      cont.appendChild procLabel
      js_top_panel_box.appendChild cont

      cont.style.position = 'absolute'
      cont.style.top = '20px'
      cont.style.left = '320px'

      fastSig = (userid, fileid, target, userkey) ->
        sha1 = new jsSHA 'SHA-1', 'TEXT'
        sha1.update "#{userid}#{fileid}#{target}0"
        tmp = sha1.getHash 'HEX'
        sha1 = new jsSHA 'SHA-1', 'TEXT'
        sha1.update "#{userkey}#{tmp}000000"
        return sha1.getHash 'HEX', {outputUpper: true}

      uploadinfo = null
      fastUpload = ({fileid, preid, filename, filesize}) ->
        tmus = (new Date()).getTime()
        tm = tmus // 1000

        GM_xmlhttpRequest
          method: 'POST'
          url: uploadinfo.url_upload + '?' + dictToQuery
            appid: 0
            appfrom: 10
            appversion: '2.0.0.0'
            format: 'json'
            isp: 0
            sig: fastSig uploadinfo.user_id, fileid, 'U_1_0', uploadinfo.userkey
            t: tm
          data: dictToForm
            api_version: '2.0.0.0'
            fileid: fileid
            filename: filename
            filesize: filesize
            preid: preid
            target: 'U_1_0'
            userid: uploadinfo.user_id
          responseType: 'json'
          headers:
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
          onload: (response)->
            if response.status is 200
              if response.response.status is 2
                alert 'fastupload OK, refresh window and goto root folder to find it'
              else
                alert 'fastupload FAIL, LOL'
            else
              GM_log "response.status = #{response.status}"

      getUserKey = (param) ->
        GM_xmlhttpRequest
          method: 'GET'
          url: 'http://proapi.115.com/app/uploadinfo'
          responseType: 'json'
          onload: (response)->
            if response.status is 200
              uploadinfo = response.response

              fastUpload param

            else
              GM_log "response.status = #{response.status}"

      finput.onchange = (e)->
        return if e.target.files.length is 0
        f = e.target.files[0]

        if f.size < 128 * 1024
          alert 'file size less than 128K'
          return

        PSIZE = 1 * 1024 * 1024
        npart = (f.size + PSIZE - 1) // PSIZE

        allSha1 = new jsSHA 'SHA-1', 'ARRAYBUFFER'
        preid = ''

        finalPart = ->
          fileid = allSha1.getHash 'HEX', {outputUpper: true}
          param = {fileid, preid, filename: f.name, filesize: f.size}

          if uploadinfo?
            fastUpload param
          else
            getUserKey param

        nextPart = (n) ->
          reader = new FileReader()
          b = f[n * PSIZE ... if (n + 1) * PSIZE > f.size then f.size else (n + 1) * PSIZE]

          reader.onerror = (e) ->
            GM_log "#{e.target.error}"

          reader.onload = (e) ->
            data = new Uint8Array e.target.result

            if n is 0
              sha1 = new jsSHA 'SHA-1', 'ARRAYBUFFER'
              sha1.update data[0...128 * 1024]
              preid = sha1.getHash 'HEX', {outputUpper: true}
            allSha1.update data

            procLabel.textContent = "(#{(n + 1) * 100 // npart}%)"

            if n is npart - 1
              finalPart()
            else
              nextPart n + 1

          reader.readAsArrayBuffer b

        nextPart 0

    if unsafeWindow.UPLOAD_CONFIG_H5?
      fakeSizeLimitGetter = ->
        return 115 * 1024 * 1024 * 1024
      if Object.defineProperty?
        Object.defineProperty unsafeWindow.UPLOAD_CONFIG_H5, 'size_limit', {get: fakeSizeLimitGetter}
      else if Object.prototype.__defineGetter__?
        unsafeWindow.UPLOAD_CONFIG_H5.__defineGetter__ 'size_limit', fakeSizeLimitGetter

  catch error
    GM_log "#{error.message}\n#{error.stack}"

`})()`
