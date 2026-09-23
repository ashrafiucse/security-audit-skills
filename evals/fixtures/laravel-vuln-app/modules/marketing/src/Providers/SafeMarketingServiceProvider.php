<?php

namespace Modules\Marketing\Providers;

use Illuminate\Support\ServiceProvider;
use Laravel\Pennant\Feature;
use App\Models\Tenant;

class SafeMarketingServiceProvider extends ServiceProvider
{
    public function register(): void
    {
    }

    public function boot(): void
    {
        // plan-driven defaults — no global true for dangerous capabilities
        Feature::define('import-leads', fn (Tenant $tenant) => $tenant->onPaidPlan());
        Feature::define('send-email', fn (Tenant $tenant) => $tenant->onPaidPlan());
    }
}
