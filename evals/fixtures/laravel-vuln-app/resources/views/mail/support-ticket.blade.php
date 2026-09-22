{{-- Fixture: Mailable HTML email — support channel. --}}
{{-- Staff open the ticket where HTML renders (webmail preview, --}}
{{-- support desk); the student message body goes in raw. --}}
<div class="ticket">
  <p>From: {{ $ticket->email }}</p>
  <div class="body">{!! $ticket->body !!}</div>
</div>
