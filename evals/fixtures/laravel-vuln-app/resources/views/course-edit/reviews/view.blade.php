{{-- Fixture: moderation DETAIL view — the one staff clicks from the queue. --}}
{{-- SEC-11: nl2br() is NOT an escape; {!! !!} bypasses Blade escaping. --}}
{{-- student-authored body renders raw in the admin origin => admin ATO. --}}
<div class="review-detail">
  <span class="status">{{ $review->status }}</span>
  <blockquote>{!! nl2br($review->body) !!}</blockquote>
</div>
