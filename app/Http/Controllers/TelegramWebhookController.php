<?php

namespace App\Http\Controllers;

use App\Actions\HandleTelegramUpdate;
use App\Notifications\Telegram\TelegramBot;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * Where Telegram posts the bot's updates (set up with `php artisan telegram:webhook`).
 * A request without the secret the webhook was set with is not from Telegram and is refused.
 */
class TelegramWebhookController extends Controller
{
    public function __invoke(Request $request, TelegramBot $bot, HandleTelegramUpdate $handleUpdate): Response
    {
        abort_unless($bot->isConfigured(), 404);
        abort_unless(hash_equals($bot->webhookSecret(), (string) $request->header('X-Telegram-Bot-Api-Secret-Token')), 403);

        $handleUpdate->handle($request->json()->all());

        return response()->noContent();
    }
}
