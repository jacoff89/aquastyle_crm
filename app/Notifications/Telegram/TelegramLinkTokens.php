<?php

namespace App\Notifications\Telegram;

use App\Models\User;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;

/**
 * One-time tokens that link a Telegram chat to an account. The settings page gives the user
 * a link to the bot with the token; the bot gets it as "/start <token>" and knows whose chat it is.
 *
 * A token lives in the cache for a while and works once. A user has at most one: asking for
 * a new link makes the previous one useless.
 */
class TelegramLinkTokens
{
    private const LIFETIME_MINUTES = 30;

    /**
     * A new token for the user.
     */
    public function issueFor(User $user): string
    {
        $this->forgetFor($user);

        // Telegram allows letters, digits, "_" and "-" in the start parameter, up to 64 characters.
        $token = Str::random(40);
        $expiresAt = now()->addMinutes(self::LIFETIME_MINUTES);

        Cache::put($this->tokenKey($token), $user->getKey(), $expiresAt);
        Cache::put($this->userKey($user), $token, $expiresAt);

        return $token;
    }

    /**
     * The user's token that has not been used or expired yet.
     */
    public function pendingFor(User $user): ?string
    {
        $token = Cache::get($this->userKey($user));

        return is_string($token) && Cache::has($this->tokenKey($token)) ? $token : null;
    }

    /**
     * The active user the token was issued to; the token stops working.
     */
    public function consume(string $token): ?User
    {
        $userId = Cache::pull($this->tokenKey($token));

        if ($userId === null) {
            return null;
        }

        $user = User::query()->whereKey($userId)->where('is_active', true)->first();

        if ($user !== null) {
            Cache::forget($this->userKey($user));
        }

        return $user;
    }

    public function forgetFor(User $user): void
    {
        $token = Cache::pull($this->userKey($user));

        if (is_string($token)) {
            Cache::forget($this->tokenKey($token));
        }
    }

    private function tokenKey(string $token): string
    {
        return "telegram-link:token:{$token}";
    }

    private function userKey(User $user): string
    {
        return "telegram-link:user:{$user->getKey()}";
    }
}
