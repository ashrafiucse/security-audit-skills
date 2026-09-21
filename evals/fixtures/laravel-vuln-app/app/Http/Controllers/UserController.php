<?php
// Fixture: intentionally insecure controller.
namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class UserController extends Controller
{
    public function store(Request $request)
    {
        // SEC-01: mass assignment of ALL request input (is_admin self-promotion)
        $user = User::create($request->all());
        return response()->json($user);
    }

    public function search(Request $request)
    {
        // SEC-02: raw SQL with concatenated user input
        return DB::select(DB::raw(
            "SELECT * FROM users WHERE name = '" . $request->input('name') . "'"
        ));
    }

    public function download(Request $request)
    {
        // SEC-05: path traversal — user-controlled path under storage
        return response()->download(storage_path('app/' . $request->input('path')));
    }
}
