<?php

namespace Modules\Marketing\Jobs;

class ProcessEmailBlast implements ShouldQueue
{
    public function handle(): void
    {
        // loads EVERY lead — no cap, no verified-only filter
        $leads = Lead::query()->get();

        foreach ($leads as $lead) {
            EmailBlastRecipient::create([
                'blast_id' => $this->dto->blastId,
                'lead_id' => $lead->id,
            ]);

            SendEmailToEmailBlastRecipient::dispatch($lead->id, $this->dto);
        }
    }
}
