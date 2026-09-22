{{-- SAFE counter-example (support channel): escaped body, plain render. --}}
{{-- HTML mail built from escaped values only; no raw echo anywhere. --}}
<div class="ticket">
  <p>From: {{ $ticket->email }}</p>
  <div class="body">{{ $ticket->body }}</div>
</div>
