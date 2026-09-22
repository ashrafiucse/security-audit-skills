<?php
// Fixture: stores the review body exactly as submitted.
namespace App\Actions;

use App\Models\Review;
use App\Http\Requests\CourseReviewRequest;

class CreateCourseReviewAction
{
    public function execute(CourseReviewRequest $request, int $courseId): Review
    {
        // Chain evidence for SEC-11: no purification/HTML sanitization on
        // the way in; 'pending' status guarantees a staff reviewer opens it
        $review = new Review();
        $review->course_id = $courseId;
        $review->user_id = $request->user()->id;
        $review->body = $request->validated('body');
        $review->status = 'pending';
        $review->save();

        return $review;
    }
}
