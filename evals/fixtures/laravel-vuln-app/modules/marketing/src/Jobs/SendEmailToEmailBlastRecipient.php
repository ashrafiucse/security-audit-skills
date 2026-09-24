<?php

namespace Modules\Marketing\Jobs;

use Illuminate\Support\Facades\Mail;
use Laravel\Pennant\Feature;

class SendEmailToEmailBlastRecipient implements ShouldQueue
{
    public function handle(): void
    {
        // the ONLY real gate — and it lives in the job, not on the route
        if (! Feature::active('send-email')) {
            return;
        }

        Mail::to($this->recipient->email)->send(
            new BlastMail($this->blast->subject, $this->blast->body)
        );
    }
}
