{{-- SAFE counter-example (vs SEC-11): escape first, nl2br second. --}}
{{-- nl2br(e(...)) keeps line breaks without re-enabling raw HTML. --}}
{{-- Still a legitimate raw-echo grep hit — disposition: verified-safe. --}}
<blockquote>{!! nl2br(e($review->body)) !!}</blockquote>
