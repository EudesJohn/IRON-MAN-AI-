// Application JavaScript volontairement vulnérable — exemple de démo.
const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");

// 1. Secret en dur (variable nommée)
const dbPassword = "hunter2!";

// 2. Clé AWS factice exposée
const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";

function getUser(userId) {
  // 3. Injection SQL par concaténation
  const query = "SELECT * FROM users WHERE id = " + userId;
  db.query(query, function (err, rows) {
    console.log(rows);
  });
}

function render(data) {
  // 4. XSS
  document.getElementById("out").innerHTML = data;
  document.write("<h1>" + data + "</h1>");
}

function processInput(input) {
  // 5. eval sur une entrée potentiellement non fiable
  eval(input);
}

function runCommand(cmd) {
  // 6. Exécution de commande système
  exec(cmd);
}

function hashPassword(pwd) {
  // 7. Hachage faible (sha1)
  return require("crypto").createHash("sha1").update(pwd).digest("hex");
}

function serveFile(file) {
  // 8. Path traversal : chemin construit dynamiquement
  return fs.readFileSync("static/" + file);
}

// TODO: réécrire cette fonction correctement
function legacyHandler(req, res) {
  res.send(req.query.name);
}
