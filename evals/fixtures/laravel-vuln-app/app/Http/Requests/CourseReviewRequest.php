<?php
// Fixture: review validation — string-only rules accept arbitrary HTML.
namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class CourseReviewRequest extends FormRequest
{
    public function rules(): array
    {
        // Chain evidence for SEC-11: 'required|string' alone accepts raw
        // HTML — no sanitization rule runs before persistence
        return [
            'body' => ['required', 'string', 'min:10'],
            'rating' => ['required', 'integer', 'between:1,5'],
        ];
    }
}
