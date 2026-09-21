{{-- Fixture: raw Blade output --}}
{{-- SEC-03: {!! !!} bypasses Blade escaping --}}
<h1>Hello {!! $name !!}</h1>
<p>Safe comparison: {{ $name }}</p>
