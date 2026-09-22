{{-- SAFE counter-example (grading channel): escape first, nl2br second. --}}
<div class="answer">
  <span class="q">{{ $question->prompt }}</span>
  <div class="a">{!! nl2br(e($answer->text)) !!}</div>
</div>
