`// ==UserScript==
// @name         fake 115Browser
// @namespace    http://github.com/kkHAIKE/fake115
// @version      1.1
// @description  非115浏览器登录115.com
// @author       kkhaike
// @match        http://115.com/*
// @grant        GM_xmlhttpRequest
// @grant        unsafeWindow
// @connect      passport.115.com
// @require      http://cdn.bootcss.com/crc-32/0.4.1/crc32.min.js
// @require      http://cdn.bootcss.com/blueimp-md5/2.3.0/js/md5.min.js
// @require      https://rawgit.com/ricmoo/aes-js/master/index.js
// @require      http://www-cs-students.stanford.edu/~tjw/jsbn/jsbn.js
// @require      http://www-cs-students.stanford.edu/~tjw/jsbn/jsbn2.js
// @require      http://www-cs-students.stanford.edu/~tjw/jsbn/prng4.js
// @require      http://www-cs-students.stanford.edu/~tjw/jsbn/rng.js
// @require      http://www-cs-students.stanford.edu/~tjw/jsbn/ec.js
// @require      http://www-cs-students.stanford.edu/~tjw/jsbn/sec.js
// @require      https://rawgit.com/kkHAIKE/node-lz4/balabala/build/lz4.js
// @run-at       document-end
// ==/UserScript==
(function() {
    'use strict'`

g_rng = new SecureRandom()
g_c = secp224r1()
g_Q = g_c.getCurve().decodePointHex '0457A29257CD2320E5D6D143322FA4BB8A3CF9D3CC623EF5EDAC62B7678A89C91A83BA800D6129F522D034C895DD2465243ADDC250953BEEBA'

Buffer = require('buffer').Buffer
LZ4 = require 'lz4'

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

hexToBytes = (h) ->
  ret = []
  for i in [0...h.length] by 2
    ret.push parseInt h[i...i + 2], 16
  return ret

intToBytes = (x) ->
  ret = []
  for i in [0...4]
    ret.push x & 0xff
    x >>= 8
  return ret

pick_rand = (n) ->
  n1 = n.subtract BigInteger.ONE
  r = new BigInteger n.bitLength(), g_rng
  r.mod(n1).add BigInteger.ONE

ec115_encode_token = (tm) ->
  d = pick_rand g_c.getN()
  G = g_c.getG()
  P = G.multiply d
  c = g_c.getCurve()
  pub = c.encodePointHex P
  y = P.getY().toBigInteger()
  pub = hexToBytes "1d#{if y.testBit(0) then "03" else "02"}#{pub[2...58]}"

  r2 = new Array 2
  g_rng.nextBytes r2

  tmp = []
  for i in [0...15]
    tmp.push pub[i] ^ r2[0]
  tmp.push r2[0]
  tmp = tmp.concat intToBytes 115
  tmp = tmp.concat intToBytes tm
  for i in [16...24]
    tmp[i] ^= r2[0]
  for i in [15...30]
    tmp.push pub[i] ^ r2[1]
  tmp.push r2[1]
  tmp = tmp.concat intToBytes 0 #cnt
  for i in [40...44]
    tmp[i] ^= r2[1]

  tmp2 = stringToBytes('^j>WD3Kr?J2gLFjD4W2y@').concat tmp
  tmp = tmp.concat intToBytes CRC32.buf(tmp2) >>> 0

  K = g_Q.multiply d

  return {
    key: hexToBytes K.getX().toBigInteger().toString 16
    token: window.btoa bytesToString tmp
  }

ec115_encode_data = (data, key) ->
  key1 = key[0...16]
  key2 = key[-16...]
  aesEcb = new aesjs.ModeOfOperation.ecb key1
  tmp = stringToBytes data

  n = tmp.length
  j = 0
  ret = []
  while n > 0
    part = []
    for i in [0...16]
      k = if n <= 0 then 0 else tmp[i + j]
      part.push key2[i] ^ k
      --n

    key2 = aesEcb.encrypt part
    ret = ret.concat key2

    j += 16
  bytesToString ret

ec115_decode_aes = (data, key) ->
  key1 = key[0...16]
  iv = key[-16...]

  aesCbc = new aesjs.ModeOfOperation.cbc key1, iv
  ret = aesCbc.decrypt data

  while ret.length > 0 and ret[ret.length - 1] is 0
    ret.pop()
  return ret

ec115_compress_decode = (data) ->
  data = new Buffer data
  p = 0
  ret = []
  while p < data.length
    len = data.readInt16LE(p) + 2
    return null if p + len > data.length

    tmp = new Buffer 0x2000
    r = LZ4.decodeBlock data[p + 2...p + len], tmp
    return null if r < 0

    ret = ret.concat Array.from tmp[0...r]
    p += len
  return ret

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

LoginEncrypt_ = ({account, passwd, environment, goto, login_type}, g) ->
  tmus = (new Date()).getTime()
  tm = tmus // 1000
  fake = md5 account

  {key, token} = ec115_encode_token tm

  data = ec115_encode_data dictToForm(
    GUID: fake[0...20]
    account: account
    device: 'jujumao' # hostname
    device_id: fake[0...12].toUpperCase() # mac
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
    ), key

  GM_xmlhttpRequest
    method: 'POST'
    url: "http://passport.115.com/?ct=encrypt&ac=login&k_ec=#{token}" #encodeURIComponent
    data: data
    binary: true
    responseType: 'arraybuffer'
    #overrideMimeType: 'text\/plain; charset=x-user-defined'
    headers:
      'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
    anonymous: true
    onload: (response)->
      if response.status is 200
        data = new Uint8Array response.response
        dec = data[data.length - 12 + 5]
        unzip = data[data.length - 12 + 4]
        data = data[0...-12]

        if dec is 1
          data = ec115_decode_aes data, key
        if unzip is 1
          data = ec115_compress_decode data

        unless data is null
          json = JSON.parse bytesToString data
          if json.state
            date = new Date()
            date.setTime date.getTime() + 7 * 24 * 3600 * 1000
            datestr = date.toGMTString()

            document.cookie = "UID=#{json.data.cookie.UID}; expires=#{datestr}; path=/; domain=115.com"
            document.cookie = "CID=#{json.data.cookie.CID}; expires=#{datestr}; path=/; domain=115.com"
            document.cookie = "SEID=#{json.data.cookie.SEID}; expires=#{datestr}; path=/; domain=115.com"
            document.cookie = "OOFL=#{json.data.user_id}; expires=#{datestr}; path=/; domain=115.com"

            json.is_two = true
            delete json.data
          unsafeWindow[g] JSON.stringify json

browserInterface = unsafeWindow.browserInterface ? {}
browserInterface.LoginEncrypt = (n,g) ->
  LoginEncrypt_ JSON.parse(n), g

unsafeWindow.browserInterface = cloneInto browserInterface, unsafeWindow, {cloneFunctions: true}

`})()`
