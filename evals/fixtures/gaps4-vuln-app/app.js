// gaps4-vuln-app — adversarial drill fixture (injection-flaws red-team).
// Every planted bug is phrased to DEFEAT the skill's documented greps as
// they existed before this drill. Fake data only.

const express = require('express');
const { spawn } = require('child_process');
const app = express();

// ---------------------------------------------------------------- browser
// bundle excerpt — comment feed. The XSS sink greps knew innerHTML /
// document.write / v-html; they did NOT know these two sinks.
function renderFeed(comment) {
  const feed = document.getElementById('feed');
  feed.insertAdjacentHTML('beforeend', comment.body);
}

function renderBio(user) {
  const bioEl = document.getElementById('bio');
  bioEl.outerHTML = user.profile.bio;
}

// ---------------------------------------------------------------- server
// Orders lookup. The single-line SQLi grep requires SELECT and the
// interpolation marker on the SAME line; this build splits them across an
// assignment — both greps walk past it.
function findOrder(req, pool) {
  const base = 'SELECT * FROM orders WHERE ref = ';
  return pool.query(base + req.params.ref);
}

// Repo tooling. exec/execSync are covered sinks; spawn with shell:true is
// the same class with a different face — argument array is NOT safe when
// the shell re-parses it.
function gitLog(userBranch) {
  const child = spawn('git', ['log', '--oneline', userBranch], { shell: true });
  return child.stdout;
}

module.exports = { renderFeed, renderBio, findOrder, gitLog };
