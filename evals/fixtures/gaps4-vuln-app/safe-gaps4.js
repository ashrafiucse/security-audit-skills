// gaps4 safe counterparts — raw vulnerable forms have ZERO literal
// occurrences here (CI-enforced via MUST_NOT_MATCH rules).

function findOrderSafe(req, pool) {
  return pool.query('SELECT * FROM orders WHERE ref = ?', [req.params.ref]);
}

function renderFeedSafe(comment) {
  const el = document.getElementById('feed');
  el.textContent = comment.body; // never parsed as HTML
}

const { execFile } = require('child_process');
function gitLogSafe(branch) {
  execFile('git', ['log', '--oneline', branch], (err, out) => out); // no shell
}
