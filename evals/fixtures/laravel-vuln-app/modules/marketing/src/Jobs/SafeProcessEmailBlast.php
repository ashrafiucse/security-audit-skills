<?php

namespace Modules\Marketing\Jobs;

class SafeProcessEmailBlast implements ShouldQueue
{
    public function handle(): void
    {
        // atomic per-tenant daily quota — consumed inside the job, not on the HTTP side
        if (! BlastQuota::consumeForTenant($this->tenantId)) {
            return;
        }

        // capped + verified-recipients-only
        Lead::query()
            ->where('verified', true)
            ->limit((int) config('marketing.blast_max_recipients', 500))
            ->get()
            ->each(fn ($lead) => SendEmailToEmailBlastRecipient::dispatch($lead->id, $this->dto));
    }
}
