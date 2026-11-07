<?php

namespace App\Http\Controllers;

use App\Events\Users\UserUpdated;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\Rules\Password;

/**
 * Changing the signed-in user's own password.
 */
class PasswordController extends Controller
{
    public function update(Request $request): RedirectResponse
    {
        $validated = $request->validate([
            'current_password' => ['required', 'current_password'],
            'password' => ['required', 'confirmed', Password::defaults()],
        ]);

        $request->user()->update([
            'password' => $validated['password'],
        ]);

        UserUpdated::dispatchChanges($request->user(), $request->user());

        return back()->with('status', 'Пароль изменён.');
    }
}
