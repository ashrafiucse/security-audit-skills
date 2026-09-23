<?php

namespace Modules\Marketing\Http\Controllers;

use Illuminate\Http\Request;
use Modules\Marketing\Jobs\ProcessEmailBlast;

class LeadController extends Controller
{
    public function composeEmail(Request $request)
    {
        // raw request data straight into the DTO — attacker-controlled subject/body
        $dto = new ComposeEmailDTO($request->all());

        ProcessEmailBlast::dispatch($dto);

        return back()->with('status', 'Blast queued.');
    }
}
