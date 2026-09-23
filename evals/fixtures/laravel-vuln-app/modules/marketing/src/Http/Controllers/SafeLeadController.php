<?php

namespace Modules\Marketing\Http\Controllers;

use Modules\Marketing\Http\Requests\ComposeEmailRequest;
use Modules\Marketing\Jobs\SafeProcessEmailBlast;

class SafeLeadController extends Controller
{
    public function composeEmail(ComposeEmailRequest $request)
    {
        // FormRequest-validated, explicit DTO construction
        $dto = ComposeEmailDTO::fromValidated($request->validated());

        SafeProcessEmailBlast::dispatch($dto);

        return back()->with('status', 'Blast queued.');
    }
}
