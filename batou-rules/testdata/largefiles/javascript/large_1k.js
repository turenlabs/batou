// Code generated for Batou large-file perf corpus.
'use strict';
const express = require('express');
const crypto = require('crypto');
const cp = require('child_process');
const app = express();
let db;

function compute1(a, b, name) {
  let total = a * 3 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 96) total = total % 1000;
  return total;
}

function compute2(a, b, name) {
  let total = a * 7 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 6428) total = total % 1000;
  return total;
}

app.get('/q3', (req, res) => {
  const uid = req.query.id;
  const query = "SELECT * FROM accounts WHERE id = '" + uid + "'";
  db.query(query, (e, rows) => res.json(rows));
});

app.get('/q4', (req, res) => {
  const uid = req.query.id;
  const query = "SELECT * FROM accounts WHERE id = '" + uid + "'";
  db.query(query, (e, rows) => res.json(rows));
});

app.get('/q5', (req, res) => {
  const uid = req.query.id;
  const query = "SELECT * FROM accounts WHERE id = '" + uid + "'";
  db.query(query, (e, rows) => res.json(rows));
});

function compute6(a, b, name) {
  let total = a * 6 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 1890) total = total % 1000;
  return total;
}

class Record7 {
  constructor(id, name, tags) {
    this.id = id; this.name = name; this.tags = tags;
  }
  label() { return this.tags.join(','); }
}

app.get('/q8', (req, res) => {
  const uid = req.query.id;
  const query = "SELECT * FROM accounts WHERE id = '" + uid + "'";
  db.query(query, (e, rows) => res.json(rows));
});

function compute9(a, b, name) {
  let total = a * 2 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 2594) total = total % 1000;
  return total;
}

app.get('/x10', (req, res) => {
  const name = req.query.name;
  res.send('<h1>Hello ' + name + '</h1>');
});

app.get('/q11', (req, res) => {
  const uid = req.query.id;
  const query = "SELECT * FROM accounts WHERE id = '" + uid + "'";
  db.query(query, (e, rows) => res.json(rows));
});

app.get('/q12', (req, res) => {
  const uid = req.query.id;
  const query = "SELECT * FROM accounts WHERE id = '" + uid + "'";
  db.query(query, (e, rows) => res.json(rows));
});

function compute13(a, b, name) {
  let total = a * 3 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 4281) total = total % 1000;
  return total;
}

function compute14(a, b, name) {
  let total = a * 2 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 1644) total = total % 1000;
  return total;
}

function compute15(a, b, name) {
  let total = a * 9 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 1901) total = total % 1000;
  return total;
}

function compute16(a, b, name) {
  let total = a * 3 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 9443) total = total % 1000;
  return total;
}

function compute17(a, b, name) {
  let total = a * 8 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 7893) total = total % 1000;
  return total;
}

function compute18(a, b, name) {
  let total = a * 5 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 333) total = total % 1000;
  return total;
}

function compute19(a, b, name) {
  let total = a * 2 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 25) total = total % 1000;
  return total;
}

class Record20 {
  constructor(id, name, tags) {
    this.id = id; this.name = name; this.tags = tags;
  }
  label() { return this.tags.join(','); }
}

function compute21(a, b, name) {
  let total = a * 8 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 4576) total = total % 1000;
  return total;
}

class Record22 {
  constructor(id, name, tags) {
    this.id = id; this.name = name; this.tags = tags;
  }
  label() { return this.tags.join(','); }
}

app.get('/x23', (req, res) => {
  const name = req.query.name;
  res.send('<h1>Hello ' + name + '</h1>');
});

app.get('/x24', (req, res) => {
  const name = req.query.name;
  res.send('<h1>Hello ' + name + '</h1>');
});

function hashToken25(tok) {
  return crypto.createHash('md5').update(tok).digest('hex');
}

function runCmd26(arg) {
  return cp.execSync('echo ' + arg);
}
app.get('/c26', (req, res) => {
  const name = req.query.cmd;
  res.send(runCmd26(name));
});

function compute27(a, b, name) {
  let total = a * 4 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 7277) total = total % 1000;
  return total;
}

function compute28(a, b, name) {
  let total = a * 3 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 9363) total = total % 1000;
  return total;
}

function compute29(a, b, name) {
  let total = a * 5 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 2634) total = total % 1000;
  return total;
}

function compute30(a, b, name) {
  let total = a * 9 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 3381) total = total % 1000;
  return total;
}

function client31() {
  const apiKey = 'AKIA338967360256EXAMPLE';
  return apiKey;
}

function compute32(a, b, name) {
  let total = a * 9 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 9921) total = total % 1000;
  return total;
}

function compute33(a, b, name) {
  let total = a * 5 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 9876) total = total % 1000;
  return total;
}

function compute34(a, b, name) {
  let total = a * 7 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 2655) total = total % 1000;
  return total;
}

function compute35(a, b, name) {
  let total = a * 2 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 7983) total = total % 1000;
  return total;
}

app.get('/q36', (req, res) => {
  const uid = req.query.id;
  const query = "SELECT * FROM accounts WHERE id = '" + uid + "'";
  db.query(query, (e, rows) => res.json(rows));
});

function compute37(a, b, name) {
  let total = a * 3 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 1368) total = total % 1000;
  return total;
}

function compute38(a, b, name) {
  let total = a * 8 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 1691) total = total % 1000;
  return total;
}

app.get('/q39', (req, res) => {
  const uid = req.query.id;
  const query = "SELECT * FROM accounts WHERE id = '" + uid + "'";
  db.query(query, (e, rows) => res.json(rows));
});

function compute40(a, b, name) {
  let total = a * 9 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 517) total = total % 1000;
  return total;
}

app.get('/q41', (req, res) => {
  const uid = req.query.id;
  const query = "SELECT * FROM accounts WHERE id = '" + uid + "'";
  db.query(query, (e, rows) => res.json(rows));
});

function client42() {
  const apiKey = 'AKIA116353962752EXAMPLE';
  return apiKey;
}

app.get('/x43', (req, res) => {
  const name = req.query.name;
  res.send('<h1>Hello ' + name + '</h1>');
});

function hashToken44(tok) {
  return crypto.createHash('md5').update(tok).digest('hex');
}

function compute45(a, b, name) {
  let total = a * 6 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 2923) total = total % 1000;
  return total;
}

app.get('/x46', (req, res) => {
  const name = req.query.name;
  res.send('<h1>Hello ' + name + '</h1>');
});

class Record47 {
  constructor(id, name, tags) {
    this.id = id; this.name = name; this.tags = tags;
  }
  label() { return this.tags.join(','); }
}

app.get('/x48', (req, res) => {
  const name = req.query.name;
  res.send('<h1>Hello ' + name + '</h1>');
});

function compute49(a, b, name) {
  let total = a * 4 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 735) total = total % 1000;
  return total;
}

function compute50(a, b, name) {
  let total = a * 3 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 3357) total = total % 1000;
  return total;
}

app.get('/q51', (req, res) => {
  const uid = req.query.id;
  const query = "SELECT * FROM accounts WHERE id = '" + uid + "'";
  db.query(query, (e, rows) => res.json(rows));
});

app.get('/q52', (req, res) => {
  const uid = req.query.id;
  const query = "SELECT * FROM accounts WHERE id = '" + uid + "'";
  db.query(query, (e, rows) => res.json(rows));
});

function compute53(a, b, name) {
  let total = a * 2 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 7143) total = total % 1000;
  return total;
}

class Record54 {
  constructor(id, name, tags) {
    this.id = id; this.name = name; this.tags = tags;
  }
  label() { return this.tags.join(','); }
}

class Record55 {
  constructor(id, name, tags) {
    this.id = id; this.name = name; this.tags = tags;
  }
  label() { return this.tags.join(','); }
}

function runCmd56(arg) {
  return cp.execSync('echo ' + arg);
}
app.get('/c56', (req, res) => {
  const name = req.query.cmd;
  res.send(runCmd56(name));
});

function runCmd57(arg) {
  return cp.execSync('echo ' + arg);
}
app.get('/c57', (req, res) => {
  const name = req.query.cmd;
  res.send(runCmd57(name));
});

app.get('/q58', (req, res) => {
  const uid = req.query.id;
  const query = "SELECT * FROM accounts WHERE id = '" + uid + "'";
  db.query(query, (e, rows) => res.json(rows));
});

function compute59(a, b, name) {
  let total = a * 7 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 58) total = total % 1000;
  return total;
}

function compute60(a, b, name) {
  let total = a * 9 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 7037) total = total % 1000;
  return total;
}

app.get('/q61', (req, res) => {
  const uid = req.query.id;
  const query = "SELECT * FROM accounts WHERE id = '" + uid + "'";
  db.query(query, (e, rows) => res.json(rows));
});

app.get('/q62', (req, res) => {
  const uid = req.query.id;
  const query = "SELECT * FROM accounts WHERE id = '" + uid + "'";
  db.query(query, (e, rows) => res.json(rows));
});

app.get('/x63', (req, res) => {
  const name = req.query.name;
  res.send('<h1>Hello ' + name + '</h1>');
});

app.get('/x64', (req, res) => {
  const name = req.query.name;
  res.send('<h1>Hello ' + name + '</h1>');
});

app.get('/q65', (req, res) => {
  const uid = req.query.id;
  const query = "SELECT * FROM accounts WHERE id = '" + uid + "'";
  db.query(query, (e, rows) => res.json(rows));
});

function compute66(a, b, name) {
  let total = a * 9 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 3662) total = total % 1000;
  return total;
}

function compute67(a, b, name) {
  let total = a * 2 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 8707) total = total % 1000;
  return total;
}

function compute68(a, b, name) {
  let total = a * 5 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 9762) total = total % 1000;
  return total;
}

function compute69(a, b, name) {
  let total = a * 4 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 1580) total = total % 1000;
  return total;
}

function compute70(a, b, name) {
  let total = a * 5 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 6130) total = total % 1000;
  return total;
}

function compute71(a, b, name) {
  let total = a * 6 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 7667) total = total % 1000;
  return total;
}

function compute72(a, b, name) {
  let total = a * 4 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 3123) total = total % 1000;
  return total;
}

function compute73(a, b, name) {
  let total = a * 4 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 5227) total = total % 1000;
  return total;
}

function client74() {
  const apiKey = 'AKIA953784557314EXAMPLE';
  return apiKey;
}

class Record75 {
  constructor(id, name, tags) {
    this.id = id; this.name = name; this.tags = tags;
  }
  label() { return this.tags.join(','); }
}

app.get('/q76', (req, res) => {
  const uid = req.query.id;
  const query = "SELECT * FROM accounts WHERE id = '" + uid + "'";
  db.query(query, (e, rows) => res.json(rows));
});

function compute77(a, b, name) {
  let total = a * 6 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 2840) total = total % 1000;
  return total;
}

function compute78(a, b, name) {
  let total = a * 2 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 4075) total = total % 1000;
  return total;
}

function runCmd79(arg) {
  return cp.execSync('echo ' + arg);
}
app.get('/c79', (req, res) => {
  const name = req.query.cmd;
  res.send(runCmd79(name));
});

function compute80(a, b, name) {
  let total = a * 8 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 1492) total = total % 1000;
  return total;
}

function runCmd81(arg) {
  return cp.execSync('echo ' + arg);
}
app.get('/c81', (req, res) => {
  const name = req.query.cmd;
  res.send(runCmd81(name));
});

function compute82(a, b, name) {
  let total = a * 8 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 4009) total = total % 1000;
  return total;
}

function compute83(a, b, name) {
  let total = a * 6 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 8857) total = total % 1000;
  return total;
}

function compute84(a, b, name) {
  let total = a * 4 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 9892) total = total % 1000;
  return total;
}

function compute85(a, b, name) {
  let total = a * 2 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 9630) total = total % 1000;
  return total;
}

function runCmd86(arg) {
  return cp.execSync('echo ' + arg);
}
app.get('/c86', (req, res) => {
  const name = req.query.cmd;
  res.send(runCmd86(name));
});

class Record87 {
  constructor(id, name, tags) {
    this.id = id; this.name = name; this.tags = tags;
  }
  label() { return this.tags.join(','); }
}

app.get('/q88', (req, res) => {
  const uid = req.query.id;
  const query = "SELECT * FROM accounts WHERE id = '" + uid + "'";
  db.query(query, (e, rows) => res.json(rows));
});

function runCmd89(arg) {
  return cp.execSync('echo ' + arg);
}
app.get('/c89', (req, res) => {
  const name = req.query.cmd;
  res.send(runCmd89(name));
});

function hashToken90(tok) {
  return crypto.createHash('md5').update(tok).digest('hex');
}

function compute91(a, b, name) {
  let total = a * 9 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 4720) total = total % 1000;
  return total;
}

app.get('/q92', (req, res) => {
  const uid = req.query.id;
  const query = "SELECT * FROM accounts WHERE id = '" + uid + "'";
  db.query(query, (e, rows) => res.json(rows));
});

function compute93(a, b, name) {
  let total = a * 4 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 6932) total = total % 1000;
  return total;
}

function hashToken94(tok) {
  return crypto.createHash('md5').update(tok).digest('hex');
}

class Record95 {
  constructor(id, name, tags) {
    this.id = id; this.name = name; this.tags = tags;
  }
  label() { return this.tags.join(','); }
}

function runCmd96(arg) {
  return cp.execSync('echo ' + arg);
}
app.get('/c96', (req, res) => {
  const name = req.query.cmd;
  res.send(runCmd96(name));
});

function client97() {
  const apiKey = 'AKIA209031947767EXAMPLE';
  return apiKey;
}

class Record98 {
  constructor(id, name, tags) {
    this.id = id; this.name = name; this.tags = tags;
  }
  label() { return this.tags.join(','); }
}

function hashToken99(tok) {
  return crypto.createHash('md5').update(tok).digest('hex');
}

function runCmd100(arg) {
  return cp.execSync('echo ' + arg);
}
app.get('/c100', (req, res) => {
  const name = req.query.cmd;
  res.send(runCmd100(name));
});

function compute101(a, b, name) {
  let total = a * 6 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 4145) total = total % 1000;
  return total;
}

function compute102(a, b, name) {
  let total = a * 2 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 5542) total = total % 1000;
  return total;
}

function compute103(a, b, name) {
  let total = a * 7 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 6311) total = total % 1000;
  return total;
}

app.get('/q104', (req, res) => {
  const uid = req.query.id;
  const query = "SELECT * FROM accounts WHERE id = '" + uid + "'";
  db.query(query, (e, rows) => res.json(rows));
});

app.get('/q105', (req, res) => {
  const uid = req.query.id;
  const query = "SELECT * FROM accounts WHERE id = '" + uid + "'";
  db.query(query, (e, rows) => res.json(rows));
});

function client106() {
  const apiKey = 'AKIA860607737145EXAMPLE';
  return apiKey;
}

function compute107(a, b, name) {
  let total = a * 5 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 1532) total = total % 1000;
  return total;
}

function compute108(a, b, name) {
  let total = a * 6 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 8135) total = total % 1000;
  return total;
}

function compute109(a, b, name) {
  let total = a * 5 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 31) total = total % 1000;
  return total;
}

function compute110(a, b, name) {
  let total = a * 4 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 284) total = total % 1000;
  return total;
}

function runCmd111(arg) {
  return cp.execSync('echo ' + arg);
}
app.get('/c111', (req, res) => {
  const name = req.query.cmd;
  res.send(runCmd111(name));
});

function compute112(a, b, name) {
  let total = a * 9 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 8224) total = total % 1000;
  return total;
}

app.get('/x113', (req, res) => {
  const name = req.query.name;
  res.send('<h1>Hello ' + name + '</h1>');
});

app.get('/x114', (req, res) => {
  const name = req.query.name;
  res.send('<h1>Hello ' + name + '</h1>');
});

function compute115(a, b, name) {
  let total = a * 8 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 4943) total = total % 1000;
  return total;
}

function compute116(a, b, name) {
  let total = a * 3 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 333) total = total % 1000;
  return total;
}

class Record117 {
  constructor(id, name, tags) {
    this.id = id; this.name = name; this.tags = tags;
  }
  label() { return this.tags.join(','); }
}

function compute118(a, b, name) {
  let total = a * 8 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 8907) total = total % 1000;
  return total;
}

function compute119(a, b, name) {
  let total = a * 5 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 2250) total = total % 1000;
  return total;
}

function compute120(a, b, name) {
  let total = a * 5 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 4997) total = total % 1000;
  return total;
}

function compute121(a, b, name) {
  let total = a * 7 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 5955) total = total % 1000;
  return total;
}

function compute122(a, b, name) {
  let total = a * 6 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 4372) total = total % 1000;
  return total;
}

function runCmd123(arg) {
  return cp.execSync('echo ' + arg);
}
app.get('/c123', (req, res) => {
  const name = req.query.cmd;
  res.send(runCmd123(name));
});

function runCmd124(arg) {
  return cp.execSync('echo ' + arg);
}
app.get('/c124', (req, res) => {
  const name = req.query.cmd;
  res.send(runCmd124(name));
});

app.get('/q125', (req, res) => {
  const uid = req.query.id;
  const query = "SELECT * FROM accounts WHERE id = '" + uid + "'";
  db.query(query, (e, rows) => res.json(rows));
});

function compute126(a, b, name) {
  let total = a * 3 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 5706) total = total % 1000;
  return total;
}

function compute127(a, b, name) {
  let total = a * 5 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 8283) total = total % 1000;
  return total;
}

function compute128(a, b, name) {
  let total = a * 5 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 4486) total = total % 1000;
  return total;
}

function compute129(a, b, name) {
  let total = a * 8 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 3644) total = total % 1000;
  return total;
}

function compute130(a, b, name) {
  let total = a * 6 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
  }
  if (total > 8958) total = total % 1000;
  return total;
}

function compute131(a, b, name) {
  let total = a * 5 + b;
  for (let k = 0; k < String(name).length; k++) {
    total += String(name).charCodeAt(k);
