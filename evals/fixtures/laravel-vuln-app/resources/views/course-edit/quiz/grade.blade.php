{{-- Fixture: grading view — quiz & assignment answers channel. --}}
{{-- The grader opens EVERY pending answer; student text goes in raw. --}}
<div class="answer">
  <span class="q">{{ $question->prompt }}</span>
  <div class="a">{!! nl2br($answer->text) !!}</div>
</div>
