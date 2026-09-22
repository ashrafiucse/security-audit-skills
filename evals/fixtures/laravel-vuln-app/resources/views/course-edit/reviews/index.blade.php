{{-- Fixture: moderation LIST view — escaped output, must NOT trigger. --}}
{{-- The queue table is safe: {{ }} escapes the student-authored body. --}}
<table class="review-queue">
  @foreach ($reviews as $review)
    <tr>
      <td>{{ $review->status }}</td>
      <td>{{ $review->body }}</td>
      <td><a href="{{ route('admin.reviews.view', $review) }}">Open</a></td>
    </tr>
  @endforeach
</table>
