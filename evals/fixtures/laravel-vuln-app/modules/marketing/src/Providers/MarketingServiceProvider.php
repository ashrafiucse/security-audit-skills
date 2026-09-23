<?php

namespace Modules\Marketing\Providers;

use Illuminate\Support\ServiceProvider;
use Laravel\Pennant\Feature;

class MarketingServiceProvider extends ServiceProvider
{
    public function register(): void
    {
    }

    public function boot(): void
    {
        // import enabled globally by default — no per-plan constraint
        Feature::define('import-leads', true);
        Feature::define('send-email', false);
    }
}
