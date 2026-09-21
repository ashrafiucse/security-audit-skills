<?php
// Fixture: intentionally insecure model.
namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class User extends Model
{
    // SEC-01: explicitly wide-open guard — mass assignment enabled for every column
    protected $guarded = [];
}
