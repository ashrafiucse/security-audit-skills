// gaps4 TRIAGE counter-examples — these lines FIRE the XSS greps and are
// SAFE. They exist so the precision half of the eval is exercised by
// triage (the falsifier), not by zero-occurrence. Each is documented under
// "Must NOT trigger" in expected-findings.md.

const DOMPurify = require('dompurify');

function renderRich(post) {
  const feed = document.getElementById('feed');
  feed.innerHTML = DOMPurify.sanitize(post.content);
}

function clearFeed() {
  document.getElementById('feed').innerHTML = '';
}

const VERIFIED_BADGE_SVG = '<svg class="badge" role="img"></svg>';

function renderBadge() {
  document.getElementById('badge').innerHTML = VERIFIED_BADGE_SVG;
}
